/* sync_client.c -- Cyrus synchonization client
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>

#include <netinet/tcp.h>

#include "global.h"
#include "append.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imap_proxy.h"
#include "util.h"
#include "prot.h"
#include "message_guid.h"
#include "sync_log.h"
#include "sync_support.h"
#include "cyr_lock.h"
#include "backend.h"
#include "xstrlcat.h"
#include "signals.h"
#include "cyrusdb.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* ====================================================================== */

/* Static global variables and support routines for sync_client */

extern char *optarg;
extern int optind;

static const char *servername = NULL;
static struct backend *sync_backend = NULL;
static struct protstream *sync_out = NULL;
static struct protstream *sync_in = NULL;
static struct buf tagbuf = BUF_INITIALIZER;

static struct namespace   sync_namespace;

static unsigned flags      = 0;
static int verbose         = 0;
static int verbose_logging = 0;
static int connect_once    = 0;
static int background      = 0;
static int do_compress     = 0;
static int no_copyback     = 0;

static char *prev_userid;

/* parse_success api is undocumented but my current understanding
 * is that the caller expects it to return a pointer to the position
 * within str at which base64 encoded "success data" can be found.
 * status is for passing back other status data (if required) to
 * the original caller.
 *
 * in the case of what we're doing here, there is no base64 encoded
 * 'success data', but there is a capability string that we want to
 * save.  so we grab the capability string (including the []s) and
 * chuck that in status, and then we return NULL to indicate the
 * lack of base64 data.
 */
static char *imap_sasl_parsesuccess(char *str, const char **status)
{
    syslog(LOG_DEBUG, "imap_sasl_parsesuccess(): input is: %s", str);
    if (NULL == status)  return NULL; /* nothing useful we can do */

    const char *prelude = "A01 OK "; // FIXME don't hardcode this, get it from sasl_cmd->ok
    const size_t prelude_len = strlen(prelude);

    const char *capability = "[CAPABILITY ";
    const size_t capability_len = strlen(capability);

    char *start, *end;

    if (strncmp(str, prelude, prelude_len)) {
        /* this isn't the string we expected */
        syslog(LOG_INFO, "imap_sasl_parsesuccess(): unexpected initial string contents: %s", str);
        return NULL;
    }

    start = str + prelude_len;

    if (strncmp(start, capability, capability_len)) {
        /* this isn't a capability string */
        syslog(LOG_INFO, "imap_sasl_parsesuccess(): str does not contain a capability string: %s", str);
        return NULL;
    }

    end = start + capability_len;
    while (*end != ']' && *end != '\0') {
        end++;
    }

    if (*end == '\0') {
        /* didn't find end of capability string */
        syslog(LOG_INFO, "imap_sasl_parsesuccess(): did not find end of capability string: %s", str);
        return NULL;
    }

    /* we want to keep the ], but crop the rest off */
    *++end = '\0';

    /* status gets the capability string */
    syslog(LOG_INFO, "imap_sasl_parsesuccess(): found capability string: %s", start);
    *status = start;

    /* there's no base64 data, so return NULL */
    return NULL;
}

static void imap_postcapability(struct backend *s)
{
    if (CAPA(s, CAPA_SASL_IR)) {
        /* server supports initial response in AUTHENTICATE command */
        s->prot->u.std.sasl_cmd.maxlen = USHRT_MAX;
    }
}

struct protocol_t imap_csync_protocol =
{ "imap", "imap", TYPE_STD,
  { { { 1, NULL },
      { "C01 CAPABILITY", NULL, "C01 ", imap_postcapability,
        CAPAF_MANY_PER_LINE,
        { { "AUTH", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
// FIXME doesn't work with compress at the moment for some reason
//        { "COMPRESS=DEFLATE", CAPA_COMPRESS },
// FIXME do we need these ones?
//        { "IDLE", CAPA_IDLE },
//        { "MUPDATE", CAPA_MUPDATE },
//        { "MULTIAPPEND", CAPA_MULTIAPPEND },
//        { "RIGHTS=kxte", CAPA_ACLRIGHTS },
//        { "LIST-EXTENDED", CAPA_LISTEXTENDED },
          { "SASL-IR", CAPA_SASL_IR },
          { "X-REPLICATION", CAPA_REPLICATION },
          { NULL, 0 } } },
      { "S01 STARTTLS", "S01 OK", "S01 NO", 0 },
      { "A01 AUTHENTICATE", 0, 0, "A01 OK", "A01 NO", "+ ", "*",
        &imap_sasl_parsesuccess, AUTO_CAPA_AUTH_OK },
      { "Z01 COMPRESS DEFLATE", "* ", "Z01 OK" },
      { "N01 NOOP", "* ", "N01 OK" },
      { "Q01 LOGOUT", "* ", "Q01 " } } }
};

static struct protocol_t csync_protocol =
{ "csync", "csync", TYPE_STD,
  { { { 1, "* OK" },
      { NULL, NULL, "* OK", NULL,
        CAPAF_ONE_PER_LINE|CAPAF_SKIP_FIRST_WORD,
        { { "SASL", CAPA_AUTH },
          { "STARTTLS", CAPA_STARTTLS },
          { "COMPRESS=DEFLATE", CAPA_COMPRESS },
          { NULL, 0 } } },
      { "STARTTLS", "OK", "NO", 1 },
      { "AUTHENTICATE", USHRT_MAX, 0, "OK", "NO", "+ ", "*", NULL, 0 },
      { "COMPRESS DEFLATE", NULL, "OK" },
      { "NOOP", NULL, "OK" },
      { "EXIT", NULL, "OK" } } }
};

static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    seen_done();
    annotatemore_close();
    annotate_done();
    quotadb_close();
    quotadb_done();
    mboxlist_close();
    mboxlist_done();
    cyrus_done();
    exit(code);
}

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s -S <servername> [-C <alt_config>] [-r] [-v] mailbox...\n", name);

    exit(EC_USAGE);
}

EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    abort();
    exit(code);
}

/* ====================================================================== */

static int do_unuser(const char *userid)
{
    const char *cmd = "UNUSER";
    struct mailbox *mailbox = NULL;
    char buf[MAX_MAILBOX_BUFFER];
    struct dlist *kl;
    int r;

    /* check local mailbox first */
    (sync_namespace.mboxname_tointernal)(&sync_namespace, "INBOX",
                                          userid, buf);
    r = mailbox_open_irl(buf, &mailbox);

    /* only remove from server if there's no local mailbox */
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        kl = dlist_setatom(NULL, cmd, userid);
        sync_send_apply(kl, sync_out);
        dlist_free(&kl);

        r = sync_parse_response(cmd, sync_in, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
    }

    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

static int user_sub(const char *userid, const char *mboxname)
{
    int r;

    r = mboxlist_checksub(mboxname, userid);

    switch (r) {
    case CYRUSDB_OK:
        return sync_set_sub(userid, mboxname, 1, sync_backend, flags);
    case CYRUSDB_NOTFOUND:
        return sync_set_sub(userid, mboxname, 0, sync_backend, flags);
    default:
        return r;
    }
}

/* ====================================================================== */

static int do_unmailbox(const char *mboxname, struct backend *sync_be,
                        unsigned flags)
{
    struct mailbox *mailbox = NULL;
    int r;

    r = mailbox_open_irl(mboxname, &mailbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = sync_folder_delete(mboxname, sync_be, flags);
        if (r) {
            syslog(LOG_ERR, "folder_delete(): failed: %s '%s'",
                   mboxname, error_message(r));
        }
    }
    mailbox_close(&mailbox);

    return r;
}

/* ====================================================================== */

static void remove_meta(char *user, struct sync_action_list *list)
{
    struct sync_action *action;

    for (action = list->head ; action ; action = action->next) {
        if (!strcmp(user, action->user)) {
            action->active = 0;
        }
    }
}

/* ====================================================================== */

static int do_sync_mailboxes(struct sync_name_list *mboxname_list,
                             struct sync_action_list *user_list,
                             unsigned flags)
{
    int r = 0;

    if (mboxname_list->count) {
        r = sync_do_mailboxes(mboxname_list, sync_backend, flags);
        if (r) {
            /* promote failed personal mailboxes to USER */
            int nonuser = 0;
            struct sync_name *mbox;
            const char *userid;

            for (mbox = mboxname_list->head; mbox; mbox = mbox->next) {
                /* done OK?  Good :) */
                if (mbox->mark)
                    continue;

                userid = mboxname_to_userid(mbox->name);
                if (userid) {
                    mbox->mark = 1;

                    sync_action_list_add(user_list, NULL, userid);
                    if (verbose) {
                        printf("  Promoting: MAILBOX %s -> USER %s\n",
                               mbox->name, userid);
                    }
                    if (verbose_logging) {
                        syslog(LOG_INFO, "  Promoting: MAILBOX %s -> USER %s",
                               mbox->name, userid);
                    }
                }
                else
                    nonuser = 1; /* there was a non-user mailbox */
            }
            if (!nonuser) r = 0;
        }
    }

    return r;
}

static int do_restart()
{
    static int restartcnt = 0;

    if (sync_out->userdata) {
        /* IMAP flavor (w/ tag) */
        struct buf *tag = (struct buf *) sync_out->userdata;
        buf_reset(tag);
        buf_printf(tag, "R%d", restartcnt++);
        prot_printf(sync_out, "%s SYNC", buf_cstring(tag));
    }
    prot_printf(sync_out, "RESTART\r\n");
    prot_flush(sync_out);
    return sync_parse_response("RESTART", sync_in, NULL);
}

static int do_sync(sync_log_reader_t *slr)
{
    struct sync_action_list *user_list = sync_action_list_create();
    struct sync_action_list *unuser_list = sync_action_list_create();
    struct sync_action_list *meta_list = sync_action_list_create();
    struct sync_action_list *mailbox_list = sync_action_list_create();
    struct sync_action_list *unmailbox_list = sync_action_list_create();
    struct sync_action_list *quota_list = sync_action_list_create();
    struct sync_action_list *annot_list = sync_action_list_create();
    struct sync_action_list *seen_list = sync_action_list_create();
    struct sync_action_list *sub_list = sync_action_list_create();
    struct sync_name_list *mboxname_list = sync_name_list_create();
    const char *args[3];
    struct sync_action *action;
    int r = 0;

    while (1) {
        r = sync_log_reader_getitem(slr, args);
        if (r == EOF) break;

        if (!strcmp(args[0], "USER"))
            sync_action_list_add(user_list, NULL, args[1]);
        else if (!strcmp(args[0], "UNUSER"))
            sync_action_list_add(unuser_list, NULL, args[1]);
        else if (!strcmp(args[0], "META"))
            sync_action_list_add(meta_list, NULL, args[1]);
        else if (!strcmp(args[0], "SIEVE"))
            sync_action_list_add(meta_list, NULL, args[1]);
        else if (!strcmp(args[0], "APPEND")) /* just a mailbox event */
            sync_action_list_add(mailbox_list, args[1], NULL);
        else if (!strcmp(args[0], "MAILBOX"))
            sync_action_list_add(mailbox_list, args[1], NULL);
        else if (!strcmp(args[0], "UNMAILBOX"))
            sync_action_list_add(unmailbox_list, args[1], NULL);
        else if (!strcmp(args[0], "QUOTA"))
            sync_action_list_add(quota_list, args[1], NULL);
        else if (!strcmp(args[0], "ANNOTATION"))
            sync_action_list_add(annot_list, args[1], NULL);
        else if (!strcmp(args[0], "SEEN"))
            sync_action_list_add(seen_list, args[2], args[1]);
        else if (!strcmp(args[0], "SUB"))
            sync_action_list_add(sub_list, args[2], args[1]);
        else if (!strcmp(args[0], "UNSUB"))
            sync_action_list_add(sub_list, args[2], args[1]);
        else
            syslog(LOG_ERR, "Unknown action type: %s", args[0]);
    }

    /* Optimise out redundant clauses */

    for (action = user_list->head; action; action = action->next) {
        /* remove per-user items */
        remove_meta(action->user, meta_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
    }

    /* duplicate removal for unuser - we also strip all the user events */
    for (action = unuser_list->head; action; action = action->next) {
        /* remove per-user items */
        remove_meta(action->user, meta_list);
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);

        /* unuser trumps user */
        remove_meta(action->user, user_list);
    }

    for (action = meta_list->head; action; action = action->next) {
        /* META action overrides any user SEEN or SUB/UNSUB action
           for same user */
        remove_meta(action->user, seen_list);
        remove_meta(action->user, sub_list);
    }

    /* And then run tasks. */
    for (action = quota_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        if (sync_do_quota(action->name, sync_backend, flags)) {
            /* XXX - bogus handling, should be user */
            sync_action_list_add(mailbox_list, action->name, NULL);
            if (verbose) {
                printf("  Promoting: QUOTA %s -> MAILBOX %s\n",
                       action->name, action->name);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: QUOTA %s -> MAILBOX %s",
                       action->name, action->name);
            }
        }
    }

    for (action = annot_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        /* NOTE: ANNOTATION "" is a special case - it's a server
         * annotation, hence the check for a character at the
         * start of the name */
        if (sync_do_annotation(action->name, sync_backend,
                               flags) && *action->name) {
            /* XXX - bogus handling, should be ... er, something */
            sync_action_list_add(mailbox_list, action->name, NULL);
            if (verbose) {
                printf("  Promoting: ANNOTATION %s -> MAILBOX %s\n",
                       action->name, action->name);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: ANNOTATION %s -> MAILBOX %s",
                       action->name, action->name);
            }
        }
    }

    for (action = seen_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        if (sync_do_seen(action->user, action->name, sync_backend, flags)) {
            char *userid = mboxname_isusermailbox(action->name, 1);
            if (userid && !strcmp(userid, action->user)) {
                sync_action_list_add(user_list, NULL, action->user);
                if (verbose) {
                    printf("  Promoting: SEEN %s %s -> USER %s\n",
                           action->user, action->name, action->user);
                }
                if (verbose_logging) {
                    syslog(LOG_INFO, "  Promoting: SEEN %s %s -> USER %s",
                           action->user, action->name, action->user);
                }
            } else {
                sync_action_list_add(meta_list, NULL, action->user);
                if (verbose) {
                    printf("  Promoting: SEEN %s %s -> META %s\n",
                           action->user, action->name, action->user);
                }
                if (verbose_logging) {
                    syslog(LOG_INFO, "  Promoting: SEEN %s %s -> META %s",
                           action->user, action->name, action->user);
                }
            }
        }
    }

    for (action = sub_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        if (user_sub(action->user, action->name)) {
            sync_action_list_add(meta_list, NULL, action->user);
            if (verbose) {
                printf("  Promoting: SUB %s %s -> META %s\n",
                       action->user, action->name, action->user);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: SUB %s %s -> META %s",
                       action->user, action->name, action->name);
            }
        }
    }

    for (action = mailbox_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        sync_name_list_add(mboxname_list, action->name);
        /* only do up to 1000 mailboxes at a time */
        if (mboxname_list->count > 1000) {
            syslog(LOG_NOTICE, "sync_mailboxes: doing 1000");
            r = do_sync_mailboxes(mboxname_list, user_list, flags);
            if (r) goto cleanup;
            r = do_restart();
            if (r) goto cleanup;
            sync_name_list_free(&mboxname_list);
            mboxname_list = sync_name_list_create();
        }
    }

    r = do_sync_mailboxes(mboxname_list, user_list, flags);
    if (r) goto cleanup;
    r = do_restart();
    if (r) goto cleanup;

    for (action = unmailbox_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = do_unmailbox(action->name, sync_backend, flags);
        if (r) goto cleanup;
    }

    for (action = meta_list->head; action; action = action->next) {
        if (!action->active)
            continue;

        r = sync_do_meta(action->user, sync_backend, flags);
        if (r) {
            if (r == IMAP_INVALID_USER) goto cleanup;

            sync_action_list_add(user_list, NULL, action->user);
            if (verbose) {
                printf("  Promoting: META %s -> USER %s\n",
                       action->user, action->user);
            }
            if (verbose_logging) {
                syslog(LOG_INFO, "  Promoting: META %s -> USER %s",
                       action->user, action->user);
            }
        }
    }

    for (action = user_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = sync_do_user(action->user, sync_backend, flags);
        if (r) goto cleanup;
        r = do_restart();
        if (r) goto cleanup;
    }

    for (action = unuser_list->head; action; action = action->next) {
        if (!action->active)
            continue;
        r = do_unuser(action->user);
        if (r) goto cleanup;
    }

  cleanup:
    if (r) {
        if (verbose)
            fprintf(stderr, "Error in do_sync(): bailing out! %s\n", error_message(r));

        syslog(LOG_ERR, "Error in do_sync(): bailing out! %s", error_message(r));
    }

    sync_action_list_free(&user_list);
    sync_action_list_free(&unuser_list);
    sync_action_list_free(&meta_list);
    sync_action_list_free(&mailbox_list);
    sync_action_list_free(&unmailbox_list);
    sync_action_list_free(&quota_list);
    sync_action_list_free(&annot_list);
    sync_action_list_free(&seen_list);
    sync_action_list_free(&sub_list);
    sync_name_list_free(&mboxname_list);

    return r;
}

static int do_sync_filename(const char *filename)
{
    sync_log_reader_t *slr;
    int r;

    if ((filename == NULL) || !strcmp(filename, "-"))
        slr = sync_log_reader_create_with_fd(0);    /* STDIN */
    else
        slr = sync_log_reader_create_with_filename(filename);

    r = sync_log_reader_begin(slr);
    if (!r)
        r = do_sync(slr);

    sync_log_reader_end(slr);
    sync_log_reader_free(slr);
    return r;
}


/* ====================================================================== */

enum {
    RESTART_NONE = 0,
    RESTART_NORMAL,
    RESTART_RECONNECT
};

static int do_daemon_work(const char *channel, const char *sync_shutdown_file,
                   unsigned long timeout, unsigned long min_delta,
                   int *restartp)
{
    int r = 0;
    time_t session_start;
    time_t single_start;
    int    delta;
    struct stat sbuf;
    sync_log_reader_t *slr;

    *restartp = RESTART_NONE;
    slr = sync_log_reader_create_with_channel(channel);

    session_start = time(NULL);

    while (1) {
        single_start = time(NULL);

        signals_poll();

        /* Check for shutdown file */
        if (sync_shutdown_file && !stat(sync_shutdown_file, &sbuf)) {
            unlink(sync_shutdown_file);
            break;
        }

        /* See if its time to RESTART */
        if ((timeout > 0) &&
            ((single_start - session_start) > (time_t) timeout)) {
            *restartp = RESTART_NORMAL;
            break;
        }

        r = sync_log_reader_begin(slr);
        if (r) {
            /* including specifically r == IMAP_AGAIN */
            if (min_delta > 0) {
                sleep(min_delta);
            } else {
                usleep(100000);    /* 1/10th second */
            }
            continue;
        }

        /* Process the work log */
        if ((r=do_sync(slr))) {
            syslog(LOG_ERR,
                   "Processing sync log file %s failed: %s",
                   sync_log_reader_get_file_name(slr), error_message(r));
            break;
        }

        r = sync_log_reader_end(slr);
        if (r) break;

        delta = time(NULL) - single_start;

        if (((unsigned) delta < min_delta) && ((min_delta-delta) > 0))
            sleep(min_delta-delta);
    }
    sync_log_reader_free(slr);

    if (*restartp == RESTART_NORMAL) {
        r = do_restart();
        if (r) {
            syslog(LOG_ERR, "sync_client RESTART failed: %s",
                   error_message(r));
        } else {
            syslog(LOG_INFO, "sync_client RESTART succeeded");
        }
        r = 0;
    }

    return(r);
}

static int get_intconfig(const char *channel, const char *val)
{
    int response = -1;

    if (channel) {
        const char *result = NULL;
        char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
        snprintf(name, MAX_MAILBOX_NAME, "%s_%s", channel, val);
        result = config_getoverflowstring(name, NULL);
        if (result) response = atoi(result);
    }

    if (response == -1) {
        if (!strcmp(val, "sync_repeat_interval"))
            response = config_getint(IMAPOPT_SYNC_REPEAT_INTERVAL);
    }

    return response;
}

static const char *get_config(const char *channel, const char *val)
{
    const char *response = NULL;

    if (channel) {
        char name[MAX_MAILBOX_NAME]; /* crazy long, but hey */
        snprintf(name, MAX_MAILBOX_NAME, "%s_%s", channel, val);
        response = config_getoverflowstring(name, NULL);
    }

    if (!response) {
        /* get the core value */
        if (!strcmp(val, "sync_host"))
            response = config_getstring(IMAPOPT_SYNC_HOST);
        else if (!strcmp(val, "sync_authname"))
            response = config_getstring(IMAPOPT_SYNC_AUTHNAME);
        else if (!strcmp(val, "sync_password"))
            response = config_getstring(IMAPOPT_SYNC_PASSWORD);
        else if (!strcmp(val, "sync_realm"))
            response = config_getstring(IMAPOPT_SYNC_REALM);
        else if (!strcmp(val, "sync_port"))
            response = config_getstring(IMAPOPT_SYNC_PORT);
        else if (!strcmp(val, "sync_shutdown_file"))
            response = config_getstring(IMAPOPT_SYNC_SHUTDOWN_FILE);
        else
            fatal("unknown config variable requested", EC_SOFTWARE);
    }

    return response;
}

static void replica_connect(const char *channel)
{
    int wait;
    struct protoent *proto;
    sasl_callback_t *cb;
    int timeout;
    const char *port, *auth_status = NULL;

    cb = mysasl_callbacks(NULL,
                          get_config(channel, "sync_authname"),
                          get_config(channel, "sync_realm"),
                          get_config(channel, "sync_password"));

    /* get the right port */
    port = get_config(channel, "sync_port");
    if (port) {
        imap_csync_protocol.service = port;
        csync_protocol.service = port;
    }

    for (wait = 15;; wait *= 2) {
        sync_backend = backend_connect(sync_backend, servername,
                                       &imap_csync_protocol, "", cb, &auth_status,
                                       (verbose > 1 ? fileno(stderr) : -1));

        if (sync_backend) {
            if (sync_backend->capability & CAPA_REPLICATION) {
                /* attach our IMAP tag buffer to our protstreams as userdata */
                sync_backend->in->userdata = sync_backend->out->userdata = &tagbuf;
                break;
            }
            else {
                backend_disconnect(sync_backend);
                sync_backend = NULL;
            }
        }

        sync_backend = backend_connect(sync_backend, servername,
                                       &csync_protocol, "", cb, NULL,
                                       (verbose > 1 ? fileno(stderr) : -1));

        if (sync_backend || auth_status || connect_once || wait > 1000) break;

        fprintf(stderr,
                "Can not connect to server '%s', retrying in %d seconds\n",
                servername, wait);
        sleep(wait);
    }

    free_callbacks(cb);
    cb = NULL;

    if (!sync_backend) {
        fprintf(stderr, "Can not connect to server '%s'\n",
                servername);
        syslog(LOG_ERR, "Can not connect to server '%s'", servername);
        _exit(1);
    }

    /* Disable Nagle's Algorithm => increase throughput
     *
     * http://en.wikipedia.org/wiki/Nagle's_algorithm
     */
    if (servername[0] != '/') {
        if (sync_backend->sock >= 0 && (proto = getprotobyname("tcp")) != NULL) {
            int on = 1;

            if (setsockopt(sync_backend->sock, proto->p_proto, TCP_NODELAY,
                           (void *) &on, sizeof(on)) != 0) {
                syslog(LOG_ERR, "unable to setsocketopt(TCP_NODELAY): %m");
            }

            /* turn on TCP keepalive if set */
            if (config_getswitch(IMAPOPT_TCP_KEEPALIVE)) {
                int r;
                int optval = 1;
                socklen_t optlen = sizeof(optval);
                struct protoent *proto = getprotobyname("TCP");

                r = setsockopt(sync_backend->sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
                if (r < 0) {
                    syslog(LOG_ERR, "unable to setsocketopt(SO_KEEPALIVE): %m");
                }
#ifdef TCP_KEEPCNT
                optval = config_getint(IMAPOPT_TCP_KEEPALIVE_CNT);
                if (optval) {
                    r = setsockopt(sync_backend->sock, proto->p_proto, TCP_KEEPCNT, &optval, optlen);
                    if (r < 0) {
                        syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPCNT): %m");
                    }
                }
#endif
#ifdef TCP_KEEPIDLE
                optval = config_getint(IMAPOPT_TCP_KEEPALIVE_IDLE);
                if (optval) {
                    r = setsockopt(sync_backend->sock, proto->p_proto, TCP_KEEPIDLE, &optval, optlen);
                    if (r < 0) {
                        syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPIDLE): %m");
                    }
                }
#endif
#ifdef TCP_KEEPINTVL
                optval = config_getint(IMAPOPT_TCP_KEEPALIVE_INTVL);
                if (optval) {
                    r = setsockopt(sync_backend->sock, proto->p_proto, TCP_KEEPINTVL, &optval, optlen);
                    if (r < 0) {
                        syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPINTVL): %m");
                    }
                }
#endif
            }
        } else {
            syslog(LOG_ERR, "unable to getprotobyname(\"tcp\"): %m");
        }
    }

#ifdef HAVE_ZLIB
    /* Does the backend support compression? */
    if (CAPA(sync_backend, CAPA_COMPRESS)) {
        prot_printf(sync_backend->out, "%s\r\n",
                    sync_backend->prot->u.std.compress_cmd.cmd);
        prot_flush(sync_backend->out);

        if (sync_parse_response("COMPRESS", sync_backend->in, NULL)) {
            if (do_compress) fatal("Failed to enable compression, aborting", EC_SOFTWARE);
            syslog(LOG_NOTICE, "Failed to enable compression, continuing uncompressed");
        }
        else {
            prot_setcompress(sync_backend->in);
            prot_setcompress(sync_backend->out);
        }
    }
    else if (do_compress) fatal("Backend does not support compression, aborting", EC_SOFTWARE);
#endif

    /* links to sockets */
    sync_in = sync_backend->in;
    sync_out = sync_backend->out;

    if (verbose > 1) {
        prot_setlog(sync_in, fileno(stderr));
        prot_setlog(sync_out, fileno(stderr));
    }

    /* Set inactivity timer */
    timeout = config_getint(IMAPOPT_SYNC_TIMEOUT);
    if (timeout < 3) timeout = 3;
    prot_settimeout(sync_in, timeout);

    /* Force use of LITERAL+ so we don't need two way communications */
    prot_setisclient(sync_in, 1);
    prot_setisclient(sync_out, 1);
}

static void replica_disconnect(void)
{
    backend_disconnect(sync_backend);
}

static void do_daemon(const char *channel, const char *sync_shutdown_file,
                      unsigned long timeout, unsigned long min_delta)
{
    int r = 0;
    int restart = 1;

    signal(SIGPIPE, SIG_IGN); /* don't fail on server disconnects */

    while (restart) {
        replica_connect(channel);
        r = do_daemon_work(channel, sync_shutdown_file,
                           timeout, min_delta, &restart);
        if (r) {
            /* See if we're still connected to the server.
             * If we are, we had some type of error, so we exit.
             * Otherwise, try reconnecting.
             */
            if (!backend_ping(sync_backend, NULL)) restart = 1;
        }
        replica_disconnect();
    }
}

static int do_mailbox(const char *mboxname, unsigned flags)
{
    struct sync_name_list *list = sync_name_list_create();
    int r;

    sync_name_list_add(list, mboxname);

    r = sync_do_mailboxes(list, sync_backend, flags);

    sync_name_list_free(&list);

    return r;
}

static int cb_allmbox(const mbentry_t *mbentry, void *rock __attribute__((unused)))
{
    const char *userid;
    int r = 0;

    userid = mboxname_to_userid(mbentry->name);

    if (userid) {
        /* skip deleted mailboxes only because the are out of order, and you would
         * otherwise have to sync the user twice thanks to our naive logic */
        if (mboxname_isdeletedmailbox(mbentry->name, NULL))
            goto done;

        /* only sync if we haven't just done the user */
        if (strcmpsafe(userid, prev_userid)) {
            printf("USER: %s\n", userid);
            r = sync_do_user(userid, sync_backend, flags);
            if (r) {
                if (verbose)
                    fprintf(stderr, "Error from do_user(%s): bailing out!\n", userid);
                syslog(LOG_ERR, "Error in do_user(%s): bailing out!", userid);
                goto done;
            }
            free(prev_userid);
            prev_userid = xstrdup(userid);
        }
    }
    else {
        /* all shared mailboxes, including DELETED ones, sync alone */
        /* XXX: batch in hundreds? */
        r = do_mailbox(mbentry->name, flags);
        if (r) {
            if (verbose)
                fprintf(stderr, "Error from do_user(%s): bailing out!\n", mbentry->name);
            syslog(LOG_ERR, "Error in do_user(%s): bailing out!", mbentry->name);
            goto done;
        }
    }

done:
    return r;
}

/* ====================================================================== */

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

enum {
    MODE_UNKNOWN = -1,
    MODE_REPEAT,
    MODE_USER,
    MODE_ALLUSER,
    MODE_MAILBOX,
    MODE_META
};

int main(int argc, char **argv)
{
    int   opt, i = 0;
    char *alt_config     = NULL;
    char *input_filename = NULL;
    int   r = 0;
    int   exit_rc = 0;
    int   mode = MODE_UNKNOWN;
    int   wait     = 0;
    int   timeout  = 600;
    int   min_delta = 0;
    const char *channel = NULL;
    const char *sync_shutdown_file = NULL;
    char buf[512];
    FILE *file;
    int len;
    int config_virtdomains;
    struct sync_name_list *mboxname_list;
    char mailboxname[MAX_MAILBOX_BUFFER];

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
        fatal("must run as the Cyrus user", EC_USAGE);
    }

    setbuf(stdout, NULL);

    while ((opt = getopt(argc, argv, "C:vlLS:F:f:w:t:d:n:rRumsozOA")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'o': /* only try to connect once */
            connect_once = 1;
            break;

        case 'v': /* verbose */
            verbose++;
            break;

        case 'l': /* verbose Logging */
            verbose_logging++;
            break;

        case 'L': /* local mailbox operations only */
            flags |= SYNC_FLAG_LOCALONLY;
            break;

        case 'S': /* Socket descriptor for server */
            servername = optarg;
            break;

        case 'F': /* Shutdown file */
            sync_shutdown_file = optarg;
            break;

        case 'f': /* input_filename used by user and mailbox modes; OR
                     alternate sync_log_file used by single-run repeat mode */
            input_filename = optarg;
            break;

        case 'n':
            channel = optarg;
            break;

        case 'w':
            wait = atoi(optarg);
            break;

        case 't':
            timeout = atoi(optarg);
            break;

        case 'd':
            min_delta = atoi(optarg);
            break;

        case 'r':
            background = 1;
            /* fallthrough */

        case 'R':
            if (mode != MODE_UNKNOWN)
                fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_REPEAT;
            break;

        case 'A':
            if (mode != MODE_UNKNOWN)
                fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_ALLUSER;
            break;

        case 'u':
            if (mode != MODE_UNKNOWN)
                fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_USER;
            break;

        case 'm':
            if (mode != MODE_UNKNOWN)
                fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_MAILBOX;
            break;

        case 's':
            if (mode != MODE_UNKNOWN)
                fatal("Mutually exclusive options defined", EC_USAGE);
            mode = MODE_META;
            break;

        case 'z':
#ifdef HAVE_ZLIB
            do_compress = 1;
#else
            fatal("Compress not available without zlib compiled in", EC_SOFTWARE);
#endif
            break;

        case 'O':
            /* don't copy changes back from server */
            no_copyback = 1;
            break;

        default:
            usage("sync_client");
        }
    }

    if (mode == MODE_UNKNOWN)
        fatal("No replication mode specified", EC_USAGE);

    if (verbose) flags |= SYNC_FLAG_VERBOSE;
    if (verbose_logging) flags |= SYNC_FLAG_LOGGING;
    if (no_copyback) flags |= SYNC_FLAG_NO_COPYBACK;

    /* fork if required */
    if (background && !input_filename && !getenv("CYRUS_ISDAEMON")) {
        int pid = fork();

        if (pid == -1) {
            perror("fork");
            exit(1);
        }

        if (pid != 0) { /* parent */
            exit(0);
        }
    }

    cyrus_init(alt_config, "sync_client",
               (verbose > 1 ? CYRUSINIT_PERROR : 0),
               CONFIG_NEED_PARTITION_DATA);

    /* get the server name if not specified */
    if (!servername)
        servername = get_config(channel, "sync_host");

    if (!servername)
        fatal("sync_host not defined", EC_SOFTWARE);

    /* Just to help with debugging, so we have time to attach debugger */
    if (wait > 0) {
        fprintf(stderr, "Waiting for %d seconds for gdb attach...\n", wait);
        sleep(wait);
    }

    /* Set namespace -- force standard (internal) */
    config_virtdomains = config_getenum(IMAPOPT_VIRTDOMAINS);
    if ((r = mboxname_init_namespace(&sync_namespace, 1)) != 0) {
        fatal(error_message(r), EC_CONFIG);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for real work */
    quotadb_init(0);
    quotadb_open(NULL);

    /* open the annotation db */
    annotate_init(NULL, NULL);
    annotatemore_open();

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    /* load the SASL plugins */
    global_sasl_init(1, 0, mysasl_cb);

    switch (mode) {
    case MODE_USER:
        /* Open up connection to server */
        replica_connect(channel);

        if (input_filename) {
            if ((file=fopen(input_filename, "r")) == NULL) {
                syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
                shut_down(1);
            }
            while (fgets(buf, sizeof(buf), file)) {
                /* Chomp, then ignore empty/comment lines. */
                if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                    buf[--len] = '\0';

                if ((len == 0) || (buf[0] == '#'))
                    continue;

                mboxname_hiersep_tointernal(&sync_namespace, buf,
                                            config_virtdomains ?
                                            strcspn(buf, "@") : 0);
                if (sync_do_user(buf, sync_backend, flags)) {
                    if (verbose)
                        fprintf(stderr,
                                "Error from sync_do_user(%s): bailing out!\n",
                                buf);
                    syslog(LOG_ERR, "Error in sync_do_user(%s): bailing out!",
                           buf);
                    exit_rc = 1;
                }
            }
            fclose(file);
        } else for (i = optind; !r && i < argc; i++) {
            mboxname_hiersep_tointernal(&sync_namespace, argv[i],
                                        config_virtdomains ?
                                        strcspn(argv[i], "@") : 0);
            if (sync_do_user(argv[i], sync_backend, flags)) {
                if (verbose)
                    fprintf(stderr, "Error from sync_do_user(%s): bailing out!\n",
                            argv[i]);
                syslog(LOG_ERR, "Error in sync_do_user(%s): bailing out!", argv[i]);
                exit_rc = 1;
            }
        }

        replica_disconnect();
        break;

    case MODE_ALLUSER:
        /* Open up connection to server */
        replica_connect(channel);

        if (mboxlist_allmbox(optind < argc ? argv[optind] : NULL, cb_allmbox, NULL, 0))
            exit_rc = 1;

        replica_disconnect();
        break;

    case MODE_MAILBOX:
        /* Open up connection to server */
        replica_connect(channel);

        mboxname_list = sync_name_list_create();
        if (input_filename) {
            if ((file=fopen(input_filename, "r")) == NULL) {
                syslog(LOG_NOTICE, "Unable to open %s: %m", input_filename);
                shut_down(1);
            }
            while (fgets(buf, sizeof(buf), file)) {
                /* Chomp, then ignore empty/comment lines. */
                if (((len=strlen(buf)) > 0) && (buf[len-1] == '\n'))
                    buf[--len] = '\0';

                if ((len == 0) || (buf[0] == '#'))
                    continue;

                (*sync_namespace.mboxname_tointernal)(&sync_namespace, buf,
                                                      NULL, mailboxname);
                if (!sync_name_lookup(mboxname_list, mailboxname))
                    sync_name_list_add(mboxname_list, mailboxname);
            }
            fclose(file);
        } else for (i = optind; i < argc; i++) {
            (*sync_namespace.mboxname_tointernal)(&sync_namespace, argv[i],
                                                   NULL, mailboxname);
            if (!sync_name_lookup(mboxname_list, mailboxname))
                sync_name_list_add(mboxname_list, mailboxname);
        }

        if (sync_do_mailboxes(mboxname_list, sync_backend, flags)) {
            if (verbose) {
                fprintf(stderr,
                        "Error from sync_do_mailboxes(): bailing out!\n");
            }
            syslog(LOG_ERR, "Error in sync_do_mailboxes(): bailing out!");
            exit_rc = 1;
        }

        sync_name_list_free(&mboxname_list);
        replica_disconnect();
        break;

    case MODE_META:
        /* Open up connection to server */
        replica_connect(channel);

        for (i = optind; i < argc; i++) {
            mboxname_hiersep_tointernal(&sync_namespace, argv[i],
                                        config_virtdomains ?
                                        strcspn(argv[i], "@") : 0);
            if (sync_do_meta(argv[i], sync_backend, flags)) {
                if (verbose) {
                    fprintf(stderr,
                            "Error from sync_do_meta(%s): bailing out!\n",
                            argv[i]);
                }
                syslog(LOG_ERR, "Error in sync_do_meta(%s): bailing out!",
                       argv[i]);
                exit_rc = 1;
            }
        }

        replica_disconnect();

        break;

    case MODE_REPEAT:
        if (input_filename) {
            /* Open up connection to server */
            replica_connect(channel);

            exit_rc = do_sync_filename(input_filename);

            replica_disconnect();
        }
        else {
            /* rolling replication */
            if (!sync_shutdown_file)
                sync_shutdown_file = get_config(channel, "sync_shutdown_file");

            if (!min_delta)
                min_delta = get_intconfig(channel, "sync_repeat_interval");

            do_daemon(channel, sync_shutdown_file, timeout, min_delta);
        }

        break;

    default:
        if (verbose) fprintf(stderr, "Nothing to do!\n");
        break;
    }

    buf_free(&tagbuf);

    shut_down(exit_rc);
}
