/* caldav_db.c -- implementation of per-user CalDAV database
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#include <syslog.h>
#include <string.h>

#include <libical/ical.h>

#include "caldav_alarm.h"
#include "caldav_db.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "httpd.h"
#include "http_dav.h"
#include "ical_support.h"
#include "libconfig.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"


struct caldav_db {
    sqldb_t *db;                        /* DB handle */
    char *sched_inbox;                  /* DB owner's scheduling Inbox */
    struct buf mailbox;                 /* buffers for copies of column text */
    struct buf resource;
    struct buf lock_token;
    struct buf lock_owner;
    struct buf lock_ownerid;
    struct buf ical_uid;
    struct buf organizer;
    struct buf dtstart;
    struct buf dtend;
    struct buf sched_tag;
};


static struct namespace caldav_namespace;
time_t caldav_epoch = -1;
time_t caldav_eternity = -1;

EXPORTED int caldav_init(void)
{
    int r;
    struct icaltimetype date;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&caldav_namespace, 1))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EC_CONFIG);
    }

    /* Get min date-time */
    date = icaltime_from_string(config_getstring(IMAPOPT_CALDAV_MINDATETIME));
    if (!icaltime_is_null_time(date)) {
        caldav_epoch = icaltime_as_timet_with_zone(date, NULL);
    }
    if (caldav_epoch == -1) caldav_epoch = INT_MIN;

    /* Get max date-time */
    date = icaltime_from_string(config_getstring(IMAPOPT_CALDAV_MAXDATETIME));
    if (!icaltime_is_null_time(date)) {
        caldav_eternity = icaltime_as_timet_with_zone(date, NULL);
    }
    if (caldav_eternity == -1) caldav_eternity = INT_MAX;

    r = sqldb_init();
    caldav_alarm_init();
    return r;
}


EXPORTED int caldav_done(void)
{
    caldav_alarm_done();
    return sqldb_done();
}

EXPORTED struct caldav_db *caldav_open_userid(const char *userid)
{
    struct caldav_db *caldavdb = NULL;

    sqldb_t *db = dav_open_userid(userid);
    if (!db) return NULL;

    caldavdb = xzmalloc(sizeof(struct caldav_db));
    caldavdb->db = db;

    /* Construct mbox name corresponding to userid's scheduling Inbox */
    caldavdb->sched_inbox = caldav_mboxname(userid, SCHED_INBOX);

    return caldavdb;
}

/* Open DAV DB corresponding to userid */
EXPORTED struct caldav_db *caldav_open_mailbox(struct mailbox *mailbox)
{
    struct caldav_db *caldavdb = NULL;
    const char *userid = mboxname_to_userid(mailbox->name);

    if (userid)
        return caldav_open_userid(userid);

    sqldb_t *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    caldavdb = xzmalloc(sizeof(struct caldav_db));
    caldavdb->db = db;

    return caldavdb;
}

/* Close DAV DB */
EXPORTED int caldav_close(struct caldav_db *caldavdb)
{
    int r = 0;

    if (!caldavdb) return 0;

    free(caldavdb->sched_inbox);
    buf_free(&caldavdb->mailbox);
    buf_free(&caldavdb->resource);
    buf_free(&caldavdb->lock_token);
    buf_free(&caldavdb->lock_owner);
    buf_free(&caldavdb->lock_ownerid);
    buf_free(&caldavdb->ical_uid);
    buf_free(&caldavdb->organizer);
    buf_free(&caldavdb->dtstart);
    buf_free(&caldavdb->dtend);
    buf_free(&caldavdb->sched_tag);

    r = sqldb_close(&caldavdb->db);

    free(caldavdb);

    return r;
}

EXPORTED int caldav_begin(struct caldav_db *caldavdb)
{
    return sqldb_begin(caldavdb->db, "caldav");
}

EXPORTED int caldav_commit(struct caldav_db *caldavdb)
{
    return sqldb_commit(caldavdb->db, "caldav");
}

EXPORTED int caldav_abort(struct caldav_db *caldavdb)
{
    return sqldb_rollback(caldavdb->db, "caldav");
}

#define RROCK_FLAG_TOMBSTONES (1<<0)
struct read_rock {
    struct caldav_db *db;
    struct caldav_data *cdata;
    int flags;
    int (*cb)(void *rock, void *data);
    void *rock;
};

static const char *column_text_to_buf(const char *text, struct buf *buf)
{
    if (text) {
        buf_setcstr(buf, text);
        text = buf_cstring(buf);
    }

    return text;
}

static void _num_to_comp_flags(struct comp_flags *flags, unsigned num)
{
    flags->recurring = num & 1;
    flags->transp = (num >> 1) & 1;
    flags->status = (num >> 2) & 3;
    flags->tzbyref = (num >> 4) & 1;
    flags->mattach = (num >> 5) & 1;
}

static unsigned _comp_flags_to_num(struct comp_flags *flags)
{
   return (flags->recurring & 1)
       + ((flags->transp & 1) << 1)
       + ((flags->status & 3) << 2)
       + ((flags->tzbyref & 1) << 4)
       + ((flags->mattach & 1) << 5);
}

#define CMD_READFIELDS                                                  \
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"          \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  comp_type, ical_uid, organizer, dtstart, dtend,"                 \
    "  comp_flags, sched_tag, alive"                                    \
    " FROM ical_objs"                                                   \

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct caldav_db *db = rrock->db;
    struct caldav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct caldav_data));

    cdata->dav.alive = sqlite3_column_int(stmt, 16);
    if (!(rrock->flags && RROCK_FLAG_TOMBSTONES) && !cdata->dav.alive)
        return 0;

    cdata->dav.rowid = sqlite3_column_int(stmt, 0);
    cdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    cdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    cdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    cdata->comp_type = sqlite3_column_int(stmt, 9);
    _num_to_comp_flags(&cdata->comp_flags, sqlite3_column_int(stmt, 14));

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
        cdata->dav.mailbox = (const char *) sqlite3_column_text(stmt, 2);
        cdata->dav.resource = (const char *) sqlite3_column_text(stmt, 3);
        cdata->dav.lock_token = (const char *) sqlite3_column_text(stmt, 5);
        cdata->dav.lock_owner = (const char *) sqlite3_column_text(stmt, 6);
        cdata->dav.lock_ownerid = (const char *) sqlite3_column_text(stmt, 7);
        cdata->ical_uid = (const char *) sqlite3_column_text(stmt, 10);
        cdata->organizer = (const char *) sqlite3_column_text(stmt, 11);
        cdata->dtstart = (const char *) sqlite3_column_text(stmt, 12);
        cdata->dtend = (const char *) sqlite3_column_text(stmt, 13);
        cdata->sched_tag = (const char *) sqlite3_column_text(stmt, 15);
        r = rrock->cb(rrock->rock, cdata);
    }
    else {
        /* For single row SELECTs like caldav_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        cdata->dav.mailbox =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
                               &db->mailbox);
        cdata->dav.resource =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
                               &db->resource);
        cdata->dav.lock_token =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 5),
                               &db->lock_token);
        cdata->dav.lock_owner =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
                               &db->lock_owner);
        cdata->dav.lock_ownerid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
                               &db->lock_ownerid);
        cdata->ical_uid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
                               &db->ical_uid);
        cdata->organizer =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 11),
                               &db->organizer);
        cdata->dtstart =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
                               &db->dtstart);
        cdata->dtend =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 13),
                               &db->dtend);
        cdata->sched_tag =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 15),
                               &db->sched_tag);
    }

    return r;
}


#define CMD_SELRSRC CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND resource = :resource;"

EXPORTED int caldav_lookup_resource(struct caldav_db *caldavdb,
                           const char *mailbox, const char *resource,
                           struct caldav_data **result,
                           int tombstones)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT, { .s = mailbox       } },
        { ":resource", SQLITE_TEXT, { .s = resource      } },
        { NULL,        SQLITE_NULL, { .s = NULL          } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    r = sqldb_exec(caldavdb->db, CMD_SELRSRC, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    /* always add the mailbox and resource, so error responses don't
     * crash out */
    cdata.dav.mailbox = mailbox;
    cdata.dav.resource = resource;

    return r;
}


#define CMD_SELUID CMD_READFIELDS \
    " WHERE ical_uid = :ical_uid AND mailbox != :inbox AND alive = 1;"

EXPORTED int caldav_lookup_uid(struct caldav_db *caldavdb, const char *ical_uid,
                               struct caldav_data **result)
{
    struct sqldb_bindval bval[] = {
        { ":ical_uid", SQLITE_TEXT, { .s = ical_uid              } },
        { ":inbox",    SQLITE_TEXT, { .s = caldavdb->sched_inbox } },
        { NULL,        SQLITE_NULL, { .s = NULL                  } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, 0, NULL, NULL };
    int r;

    /* XXX - ability to pass through the tombstones flag */

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    r = sqldb_exec(caldavdb->db, CMD_SELUID, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND alive = 1;"

EXPORTED int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
                   int (*cb)(void *rock, void *data),
                   void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, 0, cb, rock };

    /* XXX - tombstones */

    return sqldb_exec(caldavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock);
}


#define CMD_INSERT                                                      \
    "INSERT INTO ical_objs ("                                           \
    "  alive, creationdate, mailbox, resource, imap_uid, modseq,"       \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  comp_type, ical_uid, organizer, dtstart, dtend,"                 \
    "  comp_flags, sched_tag )"                                         \
    " VALUES ("                                                         \
    "  :alive, :creationdate, :mailbox, :resource, :imap_uid, :modseq," \
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"          \
    "  :comp_type, :ical_uid, :organizer, :dtstart, :dtend,"            \
    "  :comp_flags, :sched_tag );"

#define CMD_UPDATE                      \
    "UPDATE ical_objs SET"              \
    "  alive        = :alive,"          \
    "  imap_uid     = :imap_uid,"       \
    "  lock_token   = :lock_token,"     \
    "  lock_owner   = :lock_owner,"     \
    "  lock_ownerid = :lock_ownerid,"   \
    "  lock_expire  = :lock_expire,"    \
    "  comp_type    = :comp_type,"      \
    "  ical_uid     = :ical_uid,"       \
    "  modseq       = :modseq,"         \
    "  organizer    = :organizer,"      \
    "  dtstart      = :dtstart,"        \
    "  dtend        = :dtend,"          \
    "  comp_flags   = :comp_flags,"     \
    "  sched_tag    = :sched_tag"       \
    " WHERE rowid = :rowid;"

EXPORTED int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    struct sqldb_bindval bval[] = {
        { ":alive",        SQLITE_INTEGER, { .i = cdata->dav.alive        } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = cdata->dav.imap_uid     } },
        { ":modseq",       SQLITE_INTEGER, { .i = cdata->dav.modseq       } },
        { ":lock_token",   SQLITE_TEXT,    { .s = cdata->dav.lock_token   } },
        { ":lock_owner",   SQLITE_TEXT,    { .s = cdata->dav.lock_owner   } },
        { ":lock_ownerid", SQLITE_TEXT,    { .s = cdata->dav.lock_ownerid } },
        { ":lock_expire",  SQLITE_INTEGER, { .i = cdata->dav.lock_expire  } },
        { ":comp_type",    SQLITE_INTEGER, { .i = cdata->comp_type        } },
        { ":ical_uid",     SQLITE_TEXT,    { .s = cdata->ical_uid         } },
        { ":organizer",    SQLITE_TEXT,    { .s = cdata->organizer        } },
        { ":dtstart",      SQLITE_TEXT,    { .s = cdata->dtstart          } },
        { ":dtend",        SQLITE_TEXT,    { .s = cdata->dtend            } },
        { ":sched_tag",    SQLITE_TEXT,    { .s = cdata->sched_tag        } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } } };
    const char *cmd;
    int r;

    bval[13].name = ":comp_flags";
    bval[13].type = SQLITE_INTEGER;
    bval[13].val.i = _comp_flags_to_num(&cdata->comp_flags);

    if (cdata->dav.rowid) {
        cmd = CMD_UPDATE;

        bval[14].name = ":rowid";
        bval[14].type = SQLITE_INTEGER;
        bval[14].val.i = cdata->dav.rowid;
    }
    else {
        cmd = CMD_INSERT;

        bval[14].name = ":creationdate";
        bval[14].type = SQLITE_INTEGER;
        bval[14].val.i = cdata->dav.creationdate;
        bval[15].name = ":mailbox";
        bval[15].type = SQLITE_TEXT;
        bval[15].val.s = cdata->dav.mailbox;
        bval[16].name = ":resource";
        bval[16].type = SQLITE_TEXT;
        bval[16].val.s = cdata->dav.resource;
    }

    r = sqldb_exec(caldavdb->db, cmd, bval, NULL, NULL);

    return r;
}


#define CMD_DELETE "DELETE FROM ical_objs WHERE rowid = :rowid;"

EXPORTED int caldav_delete(struct caldav_db *caldavdb, unsigned rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = sqldb_exec(caldavdb->db, CMD_DELETE, bval, NULL, NULL);

    return r;
}


#define CMD_DELMBOX "DELETE FROM ical_objs WHERE mailbox = :mailbox;"

EXPORTED int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = sqldb_exec(caldavdb->db, CMD_DELMBOX, bval, NULL, NULL);

    return r;
}


/* Get time period (start/end) of a component based in RFC 4791 Sec 9.9 */
EXPORTED void caldav_get_period(icalcomponent *comp, icalcomponent_kind kind,
                       struct icalperiodtype *period)
{
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    period->start =
        icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
    period->end =
        icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);
    period->duration = icaldurationtype_null_duration();

    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
        if (icaltime_is_null_time(period->end)) {
            /* No DTEND or DURATION */
            if (icaltime_is_date(period->start)) {
                /* DTSTART is not DATE-TIME */
                struct icaldurationtype dur = icaldurationtype_null_duration();

                dur.days = 1;
                period->end = icaltime_add(period->start, dur);
            }
            else
                memcpy(&period->end, &period->start, sizeof(struct icaltimetype));
        }
        break;

#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT:
#endif
    case ICAL_VTODO_COMPONENT: {
        struct icaltimetype due = (kind == ICAL_VPOLL_COMPONENT) ?
            icalcomponent_get_dtend(comp) : icalcomponent_get_due(comp);

        if (!icaltime_is_null_time(period->start)) {
            /* Has DTSTART */
            if (icaltime_is_null_time(period->end)) {
                /* No DURATION */
                memcpy(&period->end, &period->start,
                       sizeof(struct icaltimetype));

                if (!icaltime_is_null_time(due)) {
                    /* Has DUE (DTEND for VPOLL) */
                    if (icaltime_compare(due, period->start) < 0)
                        memcpy(&period->start, &due, sizeof(struct icaltimetype));
                    if (icaltime_compare(due, period->end) > 0)
                        memcpy(&period->end, &due, sizeof(struct icaltimetype));
                }
            }
        }
        else {
            icalproperty *prop;

            /* No DTSTART */
            if (!icaltime_is_null_time(due)) {
                /* Has DUE (DTEND for VPOLL) */
                memcpy(&period->start, &due, sizeof(struct icaltimetype));
                memcpy(&period->end, &due, sizeof(struct icaltimetype));
            }
            else if ((prop =
                      icalcomponent_get_first_property(comp,
                                                       ICAL_COMPLETED_PROPERTY))) {
                /* Has COMPLETED */
                period->start =
                    icaltime_convert_to_zone(icalproperty_get_completed(prop),
                                             utc);
                memcpy(&period->end, &period->start, sizeof(struct icaltimetype));

                if ((prop =
                     icalcomponent_get_first_property(comp,
                                                      ICAL_CREATED_PROPERTY))) {
                    /* Has CREATED */
                    struct icaltimetype created =
                        icaltime_convert_to_zone(icalproperty_get_created(prop),
                                                 utc);
                    if (icaltime_compare(created, period->start) < 0)
                        memcpy(&period->start, &created, sizeof(struct icaltimetype));
                    if (icaltime_compare(created, period->end) > 0)
                        memcpy(&period->end, &created, sizeof(struct icaltimetype));
                }
            }
            else if ((prop =
                      icalcomponent_get_first_property(comp,
                                                       ICAL_CREATED_PROPERTY))) {
                /* Has CREATED */
                period->start =
                    icaltime_convert_to_zone(icalproperty_get_created(prop),
                                             utc);
                period->end =
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            }
            else {
                /* Always */
                period->start =
                    icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
                period->end =
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            }
        }
        break;
    }

    case ICAL_VJOURNAL_COMPONENT:
        if (!icaltime_is_null_time(period->start)) {
            /* Has DTSTART */
            memcpy(&period->end, &period->start,
                   sizeof(struct icaltimetype));

            if (icaltime_is_date(period->start)) {
                /* DTSTART is not DATE-TIME */
                struct icaldurationtype dur;

                dur = icaldurationtype_from_int(60*60*24 - 1);  /* P1D */
                icaltime_add(period->end, dur);
            }
        }
        else {
            /* Never */
            period->start =
                icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            period->end =
                icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
        }
        break;

    case ICAL_VFREEBUSY_COMPONENT:
        if (icaltime_is_null_time(period->start) ||
            icaltime_is_null_time(period->end)) {
            /* No DTSTART or DTEND */
            icalproperty *fb =
                icalcomponent_get_first_property(comp,
                                                 ICAL_FREEBUSY_PROPERTY);


            if (fb) {
                /* Has FREEBUSY */
                /* XXX  Convert FB period into our period */
            }
            else {
                /* Never */
                period->start =
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
                period->end =
                    icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
            }
        }
        break;

    case ICAL_VAVAILABILITY_COMPONENT:
        if (icaltime_is_null_time(period->start)) {
            /* No DTSTART */
            period->start =
                icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
        }
        if (icaltime_is_null_time(period->end)) {
            /* No DTEND */
            period->end =
                icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
        }
        break;

    default:
        break;
    }
}


/* icalcomponent_foreach_recurrence() callback to find earliest/latest time */
static void recur_cb(icalcomponent *comp, struct icaltime_span *span,
                     void *rock)
{
    struct icalperiodtype *period = (struct icalperiodtype *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
        icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
        icaltime_from_timet_with_zone(span->end, is_date, utc);

    if (icaltime_compare(start, period->start) < 0)
        memcpy(&period->start, &start, sizeof(struct icaltimetype));

    if (icaltime_compare(end, period->end) > 0)
        memcpy(&period->end, &end, sizeof(struct icaltimetype));
}


EXPORTED void caldav_make_entry(icalcomponent *ical, struct caldav_data *cdata)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned mykind = 0, recurring = 0, transp = 0, status = 0, mattach = 0;
    struct icalperiodtype span;

    /* Get iCalendar UID */
    cdata->ical_uid = icalcomponent_get_uid(comp);

    /* Get component type and optional status */
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
        mykind = CAL_COMP_VEVENT;
        switch (icalcomponent_get_status(comp)) {
        case ICAL_STATUS_CANCELLED: status = CAL_STATUS_CANCELED; break;
        case ICAL_STATUS_TENTATIVE: status = CAL_STATUS_TENTATIVE; break;
        default: status = CAL_STATUS_BUSY; break;
        }
        break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    case ICAL_VAVAILABILITY_COMPONENT: mykind = CAL_COMP_VAVAILABILITY; break;
#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT: mykind = CAL_COMP_VPOLL; break;
#endif
    default: break;
    }
    cdata->comp_type = mykind;
    cdata->comp_flags.status = status;

    /* Get organizer */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) cdata->organizer = icalproperty_get_organizer(prop)+7;
    else cdata->organizer = NULL;

    /* Get transparency */
    prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
    if (prop) {
        icalvalue *transp_val = icalproperty_get_value(prop);

        switch (icalvalue_get_transp(transp_val)) {
        case ICAL_TRANSP_TRANSPARENT:
        case ICAL_TRANSP_TRANSPARENTNOCONFLICT:
            transp = 1;
            break;

        default:
            transp = 0;
            break;
        }
    }
    cdata->comp_flags.transp = transp;

    /* Check for managed attachment */
    prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
    if (prop) {
        icalparameter *param = icalproperty_get_managedid_parameter(prop);
        if (param) mattach = 1;
    }
    cdata->comp_flags.mattach = mattach;

    /* Initialize span to be nothing */
    span.start = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
    span.end = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
    span.duration = icaldurationtype_null_duration();

    do {
        struct icalperiodtype period;
        icalproperty *rrule;

        /* Get base dtstart and dtend */
        caldav_get_period(comp, kind, &period);

        /* See if its a recurring event */
        rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
        if (rrule ||
            icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY) ||
            icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY)) {
            /* Recurring - find widest time range that includes events */
            int expand = recurring = 1;

            if (rrule) {
                struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);

                if (!icaltime_is_null_time(recur.until)) {
                    /* Recurrence ends - calculate dtend of last recurrence */
                    struct icaldurationtype duration;
                    icaltimezone *utc = icaltimezone_get_utc_timezone();

                    duration = icaltime_subtract(period.end, period.start);
                    period.end =
                        icaltime_add(icaltime_convert_to_zone(recur.until, utc),
                                     duration);

                    /* Do RDATE expansion only */
                    /* XXX  This is destructive but currently doesn't matter */
                    icalcomponent_remove_property(comp, rrule);
                    free(rrule);
                }
                else if (!recur.count) {
                    /* Recurrence never ends - set end of span to eternity */
                    span.end =
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);

                    /* Skip RRULE & RDATE expansion */
                    expand = 0;
                }
            }

            /* Expand (remaining) recurrences */
            if (expand) {
                icalcomponent_foreach_recurrence(
                    comp,
                    icaltime_from_timet_with_zone(caldav_epoch, 0, NULL),
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL),
                    recur_cb, &span);
            }
        }

        /* Check our dtstart and dtend against span */
        if (icaltime_compare(period.start, span.start) < 0)
            memcpy(&span.start, &period.start, sizeof(struct icaltimetype));

        if (icaltime_compare(period.end, span.end) > 0)
            memcpy(&span.end, &period.end, sizeof(struct icaltimetype));

    } while ((comp = icalcomponent_get_next_component(ical, kind)));

    cdata->dtstart = icaltime_as_ical_string(span.start);
    cdata->dtend = icaltime_as_ical_string(span.end);
    cdata->comp_flags.recurring = recurring;
}


EXPORTED char *caldav_mboxname(const char *userid, const char *name)
{
    struct buf boxbuf = BUF_INITIALIZER;
    char *res = NULL;

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_CALENDARPREFIX));

    if (name) {
        size_t len = strcspn(name, "/");
        buf_putc(&boxbuf, '.');
        buf_appendmap(&boxbuf, name, len);
    }

    res = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

    buf_free(&boxbuf);

    return res;
}

struct calendars_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *props;
    int rows;
};

static int _wantprop(hash_table *props, const char *name)
{
    if (!props) return 1;
    if (hash_lookup(name, props)) return 1;
    return 0;
}

static void _add_xhref(json_t *obj, const char *mboxname, const char *resource)
{
    /* XXX - look up root path from namespace? */
    struct buf buf = BUF_INITIALIZER;
    const char *userid = mboxname_to_userid(mboxname);
    if (strchr(userid, '@')) {
        buf_printf(&buf, "/dav/calendars/user/%s/%s",
                   userid, strrchr(mboxname, '.')+1);
    }
    else {
        const char *domain = httpd_extradomain ? httpd_extradomain : config_defdomain;
        buf_printf(&buf, "/dav/calendars/user/%s@%s/%s",
                   userid, domain, strrchr(mboxname, '.')+1);
    }
    if (resource) buf_printf(&buf, "/%s", resource);
    json_object_set_new(obj, "x-href", json_string(buf_cstring(&buf)));
    buf_free(&buf);
}

/*
    id: String The id of the calendar. This property is immutable.
    name: String The user-visible name of the calendar. This may be any UTF-8 string of at least 1 character in length and maximum 256 bytes in size.
    colour: String Any valid CSS colour value. The colour to be used when displaying events associated with the calendar. The colour SHOULD have sufficient contrast to be used as text on a white background.
    isVisible: Boolean Should the calendar’s events be displayed to the user at the moment?
    mayReadFreeBusy: Boolean The user may read the free-busy information for this calendar. In JMAP terms, this means the user may use this calendar as part of a filter in a getCalendarEventList call, however unless mayRead == true, the events returned for this calendar will only contain free-busy information, and be stripped of any other data. This property MUST be true if mayRead is true.
    mayReadItems: Boolean The user may fetch the events in this calendar. In JMAP terms, this means the user may use this calendar as part of a filter in a getCalendarEventList call
    mayAddItems: Boolean The user may add events to this calendar. In JMAP terms, this means the user may call setCalendarEvents to create new events in this calendar or move existing events into this calendar from another calenadr. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayModifyItems: Boolean The user may edit events in this calendar by calling setCalendarEvents with the update argument referencing events in this collection. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayRemoveItems: Boolean The user may remove events from this calendar by calling setCalendarEvents with the destroy argument referencing events in this collection, or by updating their calendarId property to a different calendar. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayRename: Boolean The user may rename the calendar. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
    mayDelete: Boolean The user may delete the calendar itself. This property MUST be false if the account to which this calendar belongs has the isReadOnly property set to true.
*/

static int getcalendars_cb(const mbentry_t *mbentry, void *rock)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;

    /* only calendars */
    if (!(mbentry->mbtype & MBTYPE_CALENDAR)) return 0;

    /* only VISIBLE calendars */
    int rights = cyrus_acl_myrights(crock->req->authstate, mbentry->acl);
    if (!(rights & ACL_LOOKUP)) return 0;

    /* OK, we want this one */
    const char *collection = strrchr(mbentry->name, '.') + 1;

    /* unless it's one of the special names... XXX - check
     * the specialuse magic on these instead */
    if (!strcmp(collection, "#calendars")) return 0;
    if (!strcmp(collection, "Inbox")) return 0;
    if (!strcmp(collection, "Outbox")) return 0;

    crock->rows++;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(collection));

    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, mbentry->name, NULL);
    }

    if (_wantprop(crock->props, "name")) {
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        struct buf attrib = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mbentry->name, displayname_annot, httpd_userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, collection);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "colour")) {
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        struct buf attrib = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
        if (!r && attrib.len)
            json_object_set_new(obj, "colour", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "isVisible")) {
        /* XXX - fill this */
    }

    if (_wantprop(crock->props, "mayReadFreeBusy")) {
        int bool = rights & DACL_READFB;
        json_object_set_new(obj, "mayReadFreeBusy", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayReadItems")) {
        int bool = rights & DACL_READ;
        json_object_set_new(obj, "mayReadItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayAddItems")) {
        int bool = rights & DACL_WRITECONT;
        json_object_set_new(obj, "mayAddItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayModifyItems")) {
        int bool = rights & DACL_WRITECONT;
        json_object_set_new(obj, "mayModifyItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayRemoveItems")) {
        int bool = rights & DACL_RMRSRC;
        json_object_set_new(obj, "mayRemoveItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayRename")) {
        int bool = rights & DACL_RMCOL;
        json_object_set_new(obj, "mayRename", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayDelete")) {
        int bool = rights & DACL_RMCOL;
        json_object_set_new(obj, "mayDelete", bool ? json_true() : json_false());
    }

    json_array_append_new(crock->array, obj);

    return 0;
}

/* jmap calendar APIs */
EXPORTED int caldav_getCalendars(struct caldav_db *caldavdb __attribute__((unused)),
                                 struct jmap_req *req)
{
    struct calendars_rock rock;
    int r;

    rock.array = json_pack("[]");
    rock.req = req;
    rock.props = NULL;
    rock.rows = 0;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, 1024, 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) goto err;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(want, i));
            const char *mboxname = caldav_mboxname(req->userid, id);
            rock.rows = 0;
            r = mboxlist_mboxtree(mboxname, &getcalendars_cb, &rock, MBOXTREE_SKIP_CHILDREN);
            if (r) goto err;
            if (!rock.rows) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    }
    else {
        r = mboxlist_usermboxtree(req->userid, &getcalendars_cb, &rock, /*flags*/0);
        if (r) goto err;
    }

    if (rock.props) free_hash_table(rock.props, NULL);

    json_t *calendars = json_pack("{}");
    json_object_set_new(calendars, "accountId", json_string(req->userid));
    json_object_set_new(calendars, "state", json_string(req->state));
    json_object_set_new(calendars, "list", rock.array);
    if (json_array_size(notfound)) {
        json_object_set_new(calendars, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(calendars, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendars"));
    json_array_append_new(item, calendars);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    return 0;

err:
    syslog(LOG_ERR, "caldav error %s", error_message(r));
    if (rock.props) free_hash_table(rock.props, NULL);
    json_decref(rock.array);
    /* XXX - free memory */
    return r;
}

static int getevents_cb(sqlite3_stmt *stmt, void *rock)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;

    const char *mboxname = (const char *)sqlite3_column_text(stmt, 2);
    const char *resource = (const char *)sqlite3_column_text(stmt, 3);
    const char *ical_uid = (const char *)sqlite3_column_text(stmt, 10);

    crock->rows++;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(ical_uid));

    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, mboxname, resource);
    }

    /* XXX - other fields */

    json_array_append_new(crock->array, obj);

    return 0;
}

#define JMAP_GETUID CMD_READFIELDS \
    " WHERE ical_uid = :ical_uid AND mailbox != :inbox AND alive = 1;"

#define JMAP_GETALL CMD_READFIELDS \
    " WHERE mailbox != :inbox AND alive = 1;"

EXPORTED int caldav_getCalendarEvents(struct caldav_db *caldavdb,
                                      struct jmap_req *req)
{
    struct sqldb_bindval bval[] = {
        { ":inbox",    SQLITE_TEXT, { .s = caldavdb->sched_inbox } },
        { ":ical_uid", SQLITE_TEXT, { .s = ""   } },
        { NULL,        SQLITE_NULL, { .s = NULL    } }
    };
    struct calendars_rock rock;
    int r;

    rock.array = json_pack("[]");
    rock.req = req;
    rock.props = NULL;
    rock.rows = 0;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, 1024, 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) goto err;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(want, i));
            bval[1].val.s = id;
            rock.rows = 0;
            r = sqldb_exec(caldavdb->db, JMAP_GETUID, bval, &getevents_cb, &rock);
            if (r) goto err;
            if (!rock.rows) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    }
    else {
        r = sqldb_exec(caldavdb->db, JMAP_GETALL, bval, &getevents_cb, &rock);
        if (r) goto err;
    }

    if (rock.props) free_hash_table(rock.props, NULL);

    json_t *events = json_pack("{}");
    json_object_set_new(events, "accountId", json_string(req->userid));
    json_object_set_new(events, "state", json_string(req->state));
    json_object_set_new(events, "list", rock.array);
    if (json_array_size(notfound)) {
        json_object_set_new(events, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(events, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEvents"));
    json_array_append_new(item, events);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    return 0;

err:
    syslog(LOG_ERR, "caldav error %s", error_message(r));
    json_decref(rock.array);
    if (rock.props) free_hash_table(rock.props, NULL);
    return r;
}

