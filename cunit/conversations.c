#if HAVE_CONFIG_H
#include <config.h>
#endif
#include "cunit/cunit.h"
#include "conversations.h"
#include "global.h"
#include "strarray.h"
#include "cyrusdb.h"
#include "libcyr_cfg.h"
#include "message.h"	    /* for VECTOR_SIZE */
#include "xmalloc.h"

#define DBDIR	"test-dbdir"
#define DBNAME	"conversations.db"
#define DBNAME2	"conversations2.db"
#define DBNAME3	"conversations.db"

static void test_open(void)
{
    int r;
    struct conversations_state *state = NULL;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_getset(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char C_MSGID[] = "<0001.1288854309@example.com>";
    static const conversation_id_t C_CID = 0x12345689abcdef0ULL;
    conversation_id_t cid;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* Database is empty, so get should succeed and report no results */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    /* set should succeed */
    r = conversations_set_msgid(state, C_MSGID, C_CID);
    CU_ASSERT_EQUAL(r, 0);

    /* get should now succeed and report the value we gave it */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID);

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* get should still succeed after the db is closed & reopened */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID);

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_abort(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char C_MSGID[] = "<0002.1288854309@example.com>";
    static const conversation_id_t C_CID = 0x10345689abcdef2ULL;
    conversation_id_t cid;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* Database is empty, so get should succeed and report no results */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    /* set should succeed */
    r = conversations_set_msgid(state, C_MSGID, C_CID);
    CU_ASSERT_EQUAL(r, 0);

    /* get should now succeed and report the value we gave it */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID);

    /* abort the txn */
    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* the set vanished with the txn abort, so get should
     * succeed and report no results */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_prune(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char C_MSGID1[] = "<0003.1288854309@example.com>";
    static const conversation_id_t C_CID1 = 0x1045689abcdef23ULL;
    time_t stamp1;
    static const char C_MSGID2[] = "<0004.1288854309@example.com>";
    static const conversation_id_t C_CID2 = 0x105689abcdef234ULL;
    time_t stamp2;
    static const char C_MSGID3[] = "<0005.1288854309@example.com>";
    static const conversation_id_t C_CID3 = 0x10689abcdef2345ULL;
    time_t stamp3;
    conversation_id_t cid;
    unsigned int nseen = 0, ndeleted = 0;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* Add keys, with delays in between */
    /* TODO: CUnit needs a time warping system */

    r = conversations_set_msgid(state, C_MSGID1, C_CID1);
    CU_ASSERT_EQUAL(r, 0);
    stamp1 = time(NULL);

    sleep(4);

    r = conversations_set_msgid(state, C_MSGID2, C_CID2);
    CU_ASSERT_EQUAL(r, 0);
    stamp2 = time(NULL);

    sleep(4);

    r = conversations_set_msgid(state, C_MSGID3, C_CID3);
    CU_ASSERT_EQUAL(r, 0);
    stamp3 = time(NULL);

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* Should be able to get all 3 msgids */

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID1, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID1);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID2);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID3, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID3);

    /* Prune out the oldest two.  Note we try to make this test
     * stable with respect to timing artifacts, such as clock
     * granularity, by careful choice of sleep times. */
    r = conversations_prune(state, stamp2+(stamp3-stamp2)/2,
			    &nseen, &ndeleted);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT(nseen >= 3);
    CU_ASSERT(ndeleted >= 2);
    CU_ASSERT(nseen - ndeleted >= 1);

    /* gets of the oldest two records should succeed
     * but report no record, and a get of the newest
     * record should succeed */

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID1, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID3, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID3);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);
}

/* Test whether it is possible to open two databases at
 * the same time. */
static void test_two(void)
{
    int r;
    struct conversations_state *state1 = NULL;
    struct conversations_state *state2 = NULL;
    static const char C_MSGID1[] = "<0006.1288854309@example.com>";
    static const conversation_id_t C_CID1 = 0x1089abcdef23456ULL;
    static const char C_MSGID2[] = "<0007.1288854309@example.com>";
    static const conversation_id_t C_CID2 = 0x109abcdef234567ULL;
    conversation_id_t cid;

    r = conversations_open_path(DBNAME, &state1);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_open_path(DBNAME2, &state2);
    CU_ASSERT_EQUAL(r, 0);

    /* Databases are empty, so gets of either msgid from either db
     * should succeed and report no results */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state1, C_MSGID1, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state1, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state2, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state2, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    /* set should succeed */
    r = conversations_set_msgid(state1, C_MSGID1, C_CID1);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_set_msgid(state2, C_MSGID2, C_CID2);
    CU_ASSERT_EQUAL(r, 0);

    /* get should now succeed and report the value we gave it
     * and not the value in the other db */
    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state1, C_MSGID1, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID1);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state1, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state2, C_MSGID1, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, NULLCONVERSATION);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state2, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID2);

    r = conversations_abort(&state1);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_abort(&state2);
    CU_ASSERT_EQUAL(r, 0);
}

/* test CID encoding */
static void test_cid_encode(void)
{
    static const conversation_id_t CID1 = 0x01089abcdef23456ULL;
    static const char STR1[] = "01089abcdef23456";
    static const conversation_id_t CID2 = NULLCONVERSATION;
    static const char STR2[] = "NIL";
    const char *r;

    r = conversation_id_encode(CID1);
    CU_ASSERT_STRING_EQUAL(r, STR1);

    r = conversation_id_encode(CID2);
    CU_ASSERT_STRING_EQUAL(r, STR2);
}

/* test CID decoding */
static void test_cid_decode(void)
{
    static const char STR1[] = "01089abcdef23456";
    static const conversation_id_t CID1 = 0x01089abcdef23456ULL;
    static const char STR2[] = "NIL";
    static const conversation_id_t CID2 = NULLCONVERSATION;
    conversation_id_t cid;
    int r;

    memset(&cid, 0x45, sizeof(cid));
    r = conversation_id_decode(&cid, STR1);
    CU_ASSERT_EQUAL(r, 1);
    CU_ASSERT_EQUAL(cid, CID1);

    memset(&cid, 0x45, sizeof(cid));
    r = conversation_id_decode(&cid, STR2);
    CU_ASSERT_EQUAL(r, 1);
    CU_ASSERT_EQUAL(cid, CID2);
}

static int num_folders(conversation_t *conv)
{
    int n = 0;
    conv_folder_t *folder;

    if (!conv) return 0;

    for (folder = conv->folders ; folder ; folder = folder->next)
	n++;

    return n;
}

static void test_cid_rename(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char FOLDER1[] = "fnarp.com!user.smurf";
    static const char FOLDER2[] = "fnarp.com!user.smurf.foo bar";
    static const char FOLDER3[] = "fnarp.com!user.smurf.quux.foonly";
    static const char C_MSGID1[] = "<0008.1288854309@example.com>";
    static const char C_MSGID2[] = "<0009.1288854309@example.com>";
    static const char C_MSGID3[] = "<0010.1288854309@example.com>";
    static const conversation_id_t C_CID1 = 0x10bcdef23456789aULL;
    static const conversation_id_t C_CID2 = 0x10cdef23456789abULL;
    conversation_id_t cid;
    conversation_t *conv;
    conv_folder_t *folder;

    /* XXX - need to fix conversations_rename_cid to have a real mailbox
     * underneath! */
    return;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* setup the records we expect */
    r = conversations_set_msgid(state, C_MSGID1, C_CID1);
    CU_ASSERT_EQUAL(r, 0);
    r = conversations_set_msgid(state, C_MSGID2, C_CID1);
    CU_ASSERT_EQUAL(r, 0);
    r = conversations_set_msgid(state, C_MSGID3, C_CID1);
    CU_ASSERT_EQUAL(r, 0);

    conv = conversation_new(state);
    CU_ASSERT_PTR_NOT_NULL(conv);

    conversation_update(state, conv, FOLDER1, /*num_records*/3,
			/*exists*/3, /*unseen*/0, /*counts*/NULL,
			/*modseq*/1);
    conversation_update(state, conv, FOLDER2, /*num_records*/3,
			/*exists*/2, /*unseen*/0, /*counts*/NULL,
			/*modseq*/8);
    conversation_update(state, conv, FOLDER3, /*num_records*/13,
			/*exists*/10, /*unseen*/0, /*counts*/NULL,
			/*modseq*/5);

    r = conversation_save(state, C_CID1, conv);
    CU_ASSERT_EQUAL(r, 0);

    /* commit & close */
    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);
    conversation_free(conv);
    conv = NULL;

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* do a rename */
    r = conversations_rename_cid(state, C_CID1, C_CID2);
    CU_ASSERT_EQUAL(r, 0);

    /* commit & close */
    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /*
     * The B records in the database are renamed immediately, so the
     * counts should all be in CID2, and CID1 should be empty
     */
    conv = NULL;
    r = conversation_load(state, C_CID2, &conv);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conv);
    CU_ASSERT_EQUAL(conv->modseq, 8);
    CU_ASSERT_EQUAL(num_folders(conv), 3);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    conversation_free(conv);
    conv = NULL;

    conv = NULL;
    r = conversation_load(state, C_CID1, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(conv);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID1, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID2);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID2, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID2);

    memset(&cid, 0x45, sizeof(cid));
    r = conversations_get_msgid(state, C_MSGID3, &cid);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(cid, C_CID2);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_folder_rename(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char FOLDER1[] = "fnarp.com!user.smurf";
    static const char FOLDER2[] = "fnarp.com!user.smurf.foo";
    static const char FOLDER3[] = "fnarp.com!user.smurf.bar";
    static const char C_MSGID1[] = "<0008.1288854309@example.com>";
    static const char C_MSGID2[] = "<0009.1288854309@example.com>";
    static const char C_MSGID3[] = "<0010.1288854309@example.com>";
    static const conversation_id_t C_CID = 0x10bcdef23456789aULL;
    conversation_t *conv;
    conv_folder_t *folder;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(state);

    /* setup the records we expect */
    r = conversations_set_msgid(state, C_MSGID1, C_CID);
    CU_ASSERT_EQUAL(r, 0);
    r = conversations_set_msgid(state, C_MSGID2, C_CID);
    CU_ASSERT_EQUAL(r, 0);
    r = conversations_set_msgid(state, C_MSGID3, C_CID);
    CU_ASSERT_EQUAL(r, 0);

    conv = conversation_new(state);
    CU_ASSERT_PTR_NOT_NULL(conv);

    conversation_update(state, conv, FOLDER1, /*num_records*/3,
			/*exists*/3, /*unseen*/0, /*counts*/NULL,
			/*modseq*/1);
    conversation_update(state, conv, FOLDER2, /*num_records*/3,
			/*exists*/2, /*unseen*/0, /*counts*/NULL,
			/*modseq*/8);

    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);

    conversation_free(conv);
    conv = NULL;

    /* commit & close */
    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* do a rename */
    r = conversations_rename_folder(state, FOLDER2, FOLDER3);
    CU_ASSERT_EQUAL(r, 0);

    /* commit & close */
    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conv);
    CU_ASSERT_EQUAL(conv->modseq, 8);
    CU_ASSERT_EQUAL(num_folders(conv), 2);
    CU_ASSERT_EQUAL(conv->exists, 5);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->exists, 3);
    /* no record for folder2 */
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    /* have a record for folder3 */
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->exists, 2);
    conversation_free(conv);
    conv = NULL;

    /* now "delete" the folder.  NOTE - this doesn't actually
     * change any counts, because we go through the CIDs
     * individually on the delete codepath */
    r = conversations_rename_folder(state, FOLDER3, NULL);
    CU_ASSERT_EQUAL(r, 0);

    conversation_free(conv);
    conv = NULL;

    /* commit & close */
    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conv);
    /* got a record for folder1 */
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->exists, 3);
    /* no record for folder2 */
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    /* no record for folder3 either */
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NULL_FATAL(folder);

    conversation_free(conv);
    conv = NULL;

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);
}

static void test_folders(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char FOLDER1[] = "foobar.com!user.smurf";
    static const char FOLDER2[] = "foobar.com!user.smurf.foo bar";
    static const char FOLDER3[] = "foobar.com!user.smurf.quux.foonly";
    static const char FOLDER_N1[] = "aaa not here";
    static const char FOLDER_N2[] = "zzz not here";
    static const conversation_id_t C_CID = 0x10abcdef23456789ULL;
    conversation_t *conv;
    conv_folder_t *folder;
    int *counts;

    /* hack to get this DB created with a counted_strings value */
    imapopts[IMAPOPT_CONVERSATIONS_COUNTED_FLAGS].val.s = "\\Draft $HasRandom";

    r = conversations_open_path(DBNAME3, &state);
    CU_ASSERT_EQUAL(r, 0);

    imapopts[IMAPOPT_CONVERSATIONS_COUNTED_FLAGS].val.s = NULL;

    CU_ASSERT_EQUAL(state->counted_flags->count, 2);

    counts = xzmalloc(sizeof(int) * state->counted_flags->count);

    /* Database is empty, so get should succeed and report no results */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(conv);

    /* update should succeed */
    conv = conversation_new(state);
    CU_ASSERT_PTR_NOT_NULL(conv);
    CU_ASSERT_EQUAL(conv->dirty, 1);

    counts[0] = 1;
    counts[1] = 0;

    conversation_update(state, conv, FOLDER1, /*num_records*/13,
			/*exists*/7, /*unseen*/5, counts,
			/*modseq*/4);

    /* make sure the data we just passed to conversation_update()
     * is present in the structure */
    CU_ASSERT_EQUAL(conv->num_records, 13);
    CU_ASSERT_EQUAL(conv->exists, 7);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 1);
    CU_ASSERT_EQUAL(conv->counts[1], 0);
    CU_ASSERT_EQUAL(conv->modseq, 4);
    CU_ASSERT_EQUAL(num_folders(conv), 1);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 13);
    CU_ASSERT_EQUAL(folder->exists, 7);
    CU_ASSERT_EQUAL(folder->modseq, 4);
    CU_ASSERT_EQUAL(conv->dirty, 1);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);

    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);
    conversation_free(conv);
    conv = NULL;

    /* get should now succeed and report the value we gave it */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);
    CU_ASSERT_EQUAL(conv->num_records, 13);
    CU_ASSERT_EQUAL(conv->exists, 7);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 1);
    CU_ASSERT_EQUAL(conv->counts[1], 0);
    CU_ASSERT_EQUAL(conv->modseq, 4);
    CU_ASSERT_EQUAL(num_folders(conv), 1);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 13);
    CU_ASSERT_EQUAL(folder->exists, 7);
    CU_ASSERT_EQUAL(folder->modseq, 4);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);

    counts[1] = 2;
    /* some more updates should succeed */
    conversation_update(state, conv, FOLDER2,/*num_records*/2,
			/*exists*/1, /*unseen*/0, counts,
			/*modseq*/7);

    CU_ASSERT_EQUAL(conv->dirty, 1);
    CU_ASSERT_EQUAL(conv->num_records, 15);
    CU_ASSERT_EQUAL(conv->exists, 8);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 2);
    CU_ASSERT_EQUAL(conv->counts[1], 2);
    CU_ASSERT_EQUAL(conv->modseq, 7);
    CU_ASSERT_EQUAL(num_folders(conv), 2);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 13);
    CU_ASSERT_EQUAL(folder->exists, 7);
    CU_ASSERT_EQUAL(folder->modseq, 4);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 2);
    CU_ASSERT_EQUAL(folder->exists, 1);
    CU_ASSERT_EQUAL(folder->modseq, 7);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);


    counts[1] = 5;
    conversation_update(state, conv, FOLDER3,/*num_records*/10,
			/*exists*/10, /*unseen*/0, counts,
			/*modseq*/55);

    CU_ASSERT_EQUAL(conv->dirty, 1);
    CU_ASSERT_EQUAL(conv->num_records, 25);
    CU_ASSERT_EQUAL(conv->exists, 18);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 3);
    CU_ASSERT_EQUAL(conv->counts[1], 7);
    CU_ASSERT_EQUAL(conv->modseq, 55);
    CU_ASSERT_EQUAL(num_folders(conv), 3);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 13);
    CU_ASSERT_EQUAL(folder->exists, 7);
    CU_ASSERT_EQUAL(folder->modseq, 4);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 2);
    CU_ASSERT_EQUAL(folder->exists, 1);
    CU_ASSERT_EQUAL(folder->modseq, 7);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 10);
    CU_ASSERT_EQUAL(folder->exists, 10);
    CU_ASSERT_EQUAL(folder->modseq, 55);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);

    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    conversation_free(conv);
    conv = NULL;

    /* get should now succeed and report all values we gave it */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);
    CU_ASSERT_EQUAL(conv->num_records, 25);
    CU_ASSERT_EQUAL(conv->exists, 18);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 3);
    CU_ASSERT_EQUAL(conv->counts[1], 7);
    CU_ASSERT_EQUAL(conv->modseq, 55);
    CU_ASSERT_EQUAL(num_folders(conv), 3);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 13);
    CU_ASSERT_EQUAL(folder->exists, 7);
    CU_ASSERT_EQUAL(folder->modseq, 4);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 2);
    CU_ASSERT_EQUAL(folder->exists, 1);
    CU_ASSERT_EQUAL(folder->modseq, 7);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 10);
    CU_ASSERT_EQUAL(folder->exists, 10);
    CU_ASSERT_EQUAL(folder->modseq, 55);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    conversation_free(conv);
    conv = NULL;

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME3, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* get should still succeed and report all values we gave it */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);
    CU_ASSERT_EQUAL(conv->num_records, 25);
    CU_ASSERT_EQUAL(conv->exists, 18);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 3);
    CU_ASSERT_EQUAL(conv->counts[1], 7);
    CU_ASSERT_EQUAL(conv->modseq, 55);
    CU_ASSERT_EQUAL(num_folders(conv), 3);
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 13);
    CU_ASSERT_EQUAL(folder->exists, 7);
    CU_ASSERT_EQUAL(folder->modseq, 4);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 2);
    CU_ASSERT_EQUAL(folder->exists, 1);
    CU_ASSERT_EQUAL(folder->modseq, 7);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 10);
    CU_ASSERT_EQUAL(folder->exists, 10);
    CU_ASSERT_EQUAL(folder->modseq, 55);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(conv->dirty, 0);

    /* decrementing a folder down to zero */
    counts[0] = -1;
    counts[1] = 0;
    conversation_update(state, conv, FOLDER1,/*num_records*/-13,
			/*exists*/-7, /*unseen*/0, counts,
			/*modseq*/56);

    CU_ASSERT_EQUAL(conv->num_records, 12);
    CU_ASSERT_EQUAL(conv->exists, 11);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 2);
    CU_ASSERT_EQUAL(conv->counts[1], 7);
    CU_ASSERT_EQUAL(conv->modseq, 56);
    CU_ASSERT_EQUAL(num_folders(conv), 3);  /* struct still in place
					       with all counters zero */
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 0);
    CU_ASSERT_EQUAL(folder->exists, 0);
    CU_ASSERT_EQUAL(folder->modseq, 56);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 2);
    CU_ASSERT_EQUAL(folder->exists, 1);
    CU_ASSERT_EQUAL(folder->modseq, 7);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 10);
    CU_ASSERT_EQUAL(folder->exists, 10);
    CU_ASSERT_EQUAL(folder->modseq, 55);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(conv->dirty, 1);

    /* folder goes away properly when saved & re-loaded */
    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    conversation_free(conv);
    conv = NULL;

    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);

    CU_ASSERT_EQUAL(conv->num_records, 12);
    CU_ASSERT_EQUAL(conv->exists, 11);
    CU_ASSERT_EQUAL(conv->unseen, 5);
    CU_ASSERT_EQUAL(conv->counts[0], 2);
    CU_ASSERT_EQUAL(conv->counts[1], 7);
    CU_ASSERT_EQUAL(conv->modseq, 56);
    CU_ASSERT_EQUAL(num_folders(conv), 2);  /* FOLDER1 gone now */
    folder = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 2);
    CU_ASSERT_EQUAL(folder->exists, 1);
    CU_ASSERT_EQUAL(folder->modseq, 7);
    folder = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL(folder);
    CU_ASSERT_EQUAL(folder->num_records, 10);
    CU_ASSERT_EQUAL(folder->exists, 10);
    CU_ASSERT_EQUAL(folder->modseq, 55);
    folder = conversation_find_folder(state, conv, FOLDER_N1);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    folder = conversation_find_folder(state, conv, FOLDER_N2);
    CU_ASSERT_PTR_NULL_FATAL(folder);
    CU_ASSERT_EQUAL(conv->dirty, 0);

    conversation_free(conv);
    conv = NULL;

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);

    free(counts);
}

static void test_folder_ordering(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char FOLDER1[] = "foobar.com!user.smurf";
    static const char FOLDER2[] = "foobar.com!user.smurf.foo bar";
    static const char FOLDER3[] = "foobar.com!user.smurf.quux.foonly";
    static const conversation_id_t C_CID = 0x10abcdef23456789ULL;
    conversation_t *conv;
    conv_folder_t *folder1;
    conv_folder_t *folder2;
    conv_folder_t *folder3;
    int *counts = 0;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* Database is empty, so get should succeed and report no results */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(conv);

    /* update should succeed */
    conv = conversation_new(state);
    CU_ASSERT_PTR_NOT_NULL(conv);
    CU_ASSERT_EQUAL(conv->dirty, 1);

    /* set up the folder names in order - we are going to discard
     * this conversation, but the folder_number call will persist */
    conversation_update(state, conv, FOLDER1, 0, 0, 0, 0, 0);
    conversation_update(state, conv, FOLDER2, 0, 0, 0, 0, 0);
    conversation_update(state, conv, FOLDER3, 0, 0, 0, 0, 0);

    /* discard and recreate */
    conversation_free(conv);
    conv = conversation_new(state);

    conversation_update(state, conv, FOLDER1, /*num_records*/1,
			/*exists*/1, /*unseen*/0, counts,
			/*modseq*/1);

    /* add folders out of order */
    conversation_update(state, conv, FOLDER3,/*num_records*/10,
			/*exists*/10, /*unseen*/0, counts,
			/*modseq*/55);

    /* save and reload here just to be sure */
    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);
    conversation_free(conv);
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);

    conversation_update(state, conv, FOLDER2,/*num_records*/2,
			/*exists*/1, /*unseen*/0, counts,
			/*modseq*/7);

    CU_ASSERT_EQUAL(conv->dirty, 1);

    /* check that they've been created in the same order */
    folder1 = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder1);
    folder2 = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder2);
    folder3 = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder3);

    /* in the right order! */
    CU_ASSERT_PTR_EQUAL(conv->folders, folder1);
    CU_ASSERT_PTR_EQUAL(folder1->next, folder2);
    CU_ASSERT_PTR_EQUAL(folder2->next, folder3);
    CU_ASSERT_PTR_NULL(folder3->next);

    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    conversation_free(conv);
    conv = NULL;

    /* get should now succeed and report the value we gave it */
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(conv->dirty, 0);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);

    /* check that they've been re-loaded in the same order */
    folder1 = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder1);
    folder2 = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder2);
    folder3 = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder3);

    /* in the right order! */
    CU_ASSERT_PTR_EQUAL(conv->folders, folder1);
    CU_ASSERT_PTR_EQUAL(folder1->next, folder2);
    CU_ASSERT_PTR_EQUAL(folder2->next, folder3);
    CU_ASSERT_PTR_NULL(folder3->next);

    conversation_free(conv);
    conv = NULL;

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* get should still succeed and report all values we gave it */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);

    /* check that they are still in the same order */
    folder1 = conversation_find_folder(state, conv, FOLDER1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder1);
    folder2 = conversation_find_folder(state, conv, FOLDER2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder2);
    folder3 = conversation_find_folder(state, conv, FOLDER3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(folder3);

    /* in the right order! */
    CU_ASSERT_PTR_EQUAL(conv->folders, folder1);
    CU_ASSERT_PTR_EQUAL(folder1->next, folder2);
    CU_ASSERT_PTR_EQUAL(folder2->next, folder3);
    CU_ASSERT_PTR_NULL(folder3->next);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);

    conversation_free(conv);
    conv = NULL;

    free(counts);
}

static void test_senders(void)
{
    int r;
    struct conversations_state *state = NULL;
    static const char FOLDER[] = "foobar.com!user.smurf";
    static const char NAME1[] = "Smurf 1";
    static const char MAILBOX1[] = "smurf";
    static const char DOMAIN1[] = "foobar.com";
    static const char NAME2[] = "Smurf 2";
    static const char MAILBOX2[] = "smurf2";
    static const char DOMAIN2[] = "foobar.com";
    static const char NAME3[] = "Aardvark";
    static const char MAILBOX3[] = "aardvark";
    static const char DOMAIN3[] = "aalphabetsoup.com";
    static const conversation_id_t C_CID = 0x10abcdef23456789ULL;
    conversation_t *conv;
    conv_sender_t *sender1;
    conv_sender_t *sender2;
    conv_sender_t *sender3;
    int *counts = 0;

    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* Database is empty, so get should succeed and report no results */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NULL(conv);

    /* update should succeed */
    conv = conversation_new(state);
    CU_ASSERT_PTR_NOT_NULL(conv);
    CU_ASSERT_EQUAL(conv->dirty, 1);

    conversation_add_sender(conv, NAME1, NULL, MAILBOX1, DOMAIN1);
    conversation_add_sender(conv, NAME2, NULL, MAILBOX2, DOMAIN2);
    conversation_add_sender(conv, NAME3, NULL, MAILBOX3, DOMAIN3);

    conversation_update(state, conv, FOLDER, /*num_records*/1,
			/*exists*/1, /*unseen*/0, counts,
			/*modseq*/1);

    /* there's no function for getting sender data, oh well */
    sender1 = conv->senders;
    CU_ASSERT_PTR_NOT_NULL(sender1);
    sender2 = sender1->next;
    CU_ASSERT_PTR_NOT_NULL(sender2);
    sender3 = sender2->next;
    CU_ASSERT_PTR_NOT_NULL(sender3);
    CU_ASSERT_PTR_NULL(sender3->next);

    /* check ordering */
    CU_ASSERT_STRING_EQUAL(sender1->name, NAME3);
    CU_ASSERT_PTR_NULL(sender1->route);
    CU_ASSERT_STRING_EQUAL(sender1->mailbox, MAILBOX3);
    CU_ASSERT_STRING_EQUAL(sender1->domain, DOMAIN3);

    CU_ASSERT_STRING_EQUAL(sender2->name, NAME1);
    CU_ASSERT_PTR_NULL(sender2->route);
    CU_ASSERT_STRING_EQUAL(sender2->mailbox, MAILBOX1);
    CU_ASSERT_STRING_EQUAL(sender2->domain, DOMAIN1);

    CU_ASSERT_STRING_EQUAL(sender3->name, NAME2);
    CU_ASSERT_PTR_NULL(sender3->route);
    CU_ASSERT_STRING_EQUAL(sender3->mailbox, MAILBOX2);
    CU_ASSERT_STRING_EQUAL(sender3->domain, DOMAIN2);

    /* save and reload here just to be sure */
    r = conversation_save(state, C_CID, conv);
    CU_ASSERT_EQUAL(r, 0);
    conversation_free(conv);
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_PTR_NOT_NULL(conv);

    /* there's no function for getting sender data, oh well */
    sender1 = conv->senders;
    CU_ASSERT_PTR_NOT_NULL(sender1);
    sender2 = sender1->next;
    CU_ASSERT_PTR_NOT_NULL(sender2);
    sender3 = sender2->next;
    CU_ASSERT_PTR_NOT_NULL(sender3);
    CU_ASSERT_PTR_NULL(sender3->next);

    /* check ordering */
    CU_ASSERT_STRING_EQUAL(sender1->name, NAME3);
    CU_ASSERT_PTR_NULL(sender1->route);
    CU_ASSERT_STRING_EQUAL(sender1->mailbox, MAILBOX3);
    CU_ASSERT_STRING_EQUAL(sender1->domain, DOMAIN3);

    CU_ASSERT_STRING_EQUAL(sender2->name, NAME1);
    CU_ASSERT_PTR_NULL(sender2->route);
    CU_ASSERT_STRING_EQUAL(sender2->mailbox, MAILBOX1);
    CU_ASSERT_STRING_EQUAL(sender2->domain, DOMAIN1);

    CU_ASSERT_STRING_EQUAL(sender3->name, NAME2);
    CU_ASSERT_PTR_NULL(sender3->route);
    CU_ASSERT_STRING_EQUAL(sender3->mailbox, MAILBOX2);
    CU_ASSERT_STRING_EQUAL(sender3->domain, DOMAIN2);

    conversation_free(conv);
    conv = NULL;

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open the db again */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    /* get should still succeed and report all values we gave it */
    conv = NULL;
    r = conversation_load(state, C_CID, &conv);

    /* there's no function for getting sender data, oh well */
    sender1 = conv->senders;
    CU_ASSERT_PTR_NOT_NULL(sender1);
    sender2 = sender1->next;
    CU_ASSERT_PTR_NOT_NULL(sender2);
    sender3 = sender2->next;
    CU_ASSERT_PTR_NOT_NULL(sender3);
    CU_ASSERT_PTR_NULL(sender3->next);

    /* check ordering */
    CU_ASSERT_STRING_EQUAL(sender1->name, NAME3);
    CU_ASSERT_PTR_NULL(sender1->route);
    CU_ASSERT_STRING_EQUAL(sender1->mailbox, MAILBOX3);
    CU_ASSERT_STRING_EQUAL(sender1->domain, DOMAIN3);

    CU_ASSERT_STRING_EQUAL(sender2->name, NAME1);
    CU_ASSERT_PTR_NULL(sender2->route);
    CU_ASSERT_STRING_EQUAL(sender2->mailbox, MAILBOX1);
    CU_ASSERT_STRING_EQUAL(sender2->domain, DOMAIN1);

    CU_ASSERT_STRING_EQUAL(sender3->name, NAME2);
    CU_ASSERT_PTR_NULL(sender3->route);
    CU_ASSERT_STRING_EQUAL(sender3->mailbox, MAILBOX2);
    CU_ASSERT_STRING_EQUAL(sender3->domain, DOMAIN2);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);

    free(counts);
}

static void gen_msgid_cid(int i, char *msgid, int msgidlen,
			  conversation_id_t *cidp)
{
    static const char * const domains[] = {
	"fastmail.fm",
	"example.com",
	"gmail.com",
	"yahoo.com",
	"hotmail.com"
    };
    snprintf(msgid, msgidlen, "<%04d.1298269537@%s>",
	    i, domains[i % VECTOR_SIZE(domains)]);

    *cidp = 0xfeeddeadbeef0000ULL | (unsigned int)i;
}

static void gen_cid_folder(int i, conversation_id_t *cidp,
			   strarray_t *mboxnames)
{
    int n;
    int j;
    static const char * const folders[] = {
	"user.foo.INBOX",
	"user.foo.Manilla",
	"user.foo.VanillaGorilla",
	"user.foo.SarsparillaGorilla"
    };

    *cidp = 0xfeeddeadbeef0000ULL | (unsigned int)i;

    strarray_truncate(mboxnames, 0);
    n = 1 + (17 - i) % (VECTOR_SIZE(folders)-1);
    CU_ASSERT(n > 0);
    for (j = 0 ; j < n ; j++)
	strarray_append(mboxnames,
			folders[(j + i/2) % VECTOR_SIZE(folders)]);
}

static void test_dump(void)
{
    int r;
    struct conversations_state *state = NULL;
    int fd;
    FILE *fp;
    char filename[64];
    char msgid[40];
    strarray_t mboxnames = STRARRAY_INITIALIZER;
    conversation_id_t cid, cid2;
    conversation_t *conv;
    conv_folder_t *folder;
    int i;
    int j;
#define N_MSGID_TO_CID	500
#define N_CID_TO_FOLDER	333
    struct stat sb;

    strcpy(filename, "/tmp/cyrus-conv.datXXXXXX");
    fd = mkstemp(filename);
    CU_ASSERT_FATAL(fd >= 0);
    fp = fdopen(fd, "r+");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);

    memset(&state, 0, sizeof(state));

    /* generate some data in the database */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    for (i = 0 ; i < N_MSGID_TO_CID ; i++) {
	gen_msgid_cid(i, msgid, sizeof(msgid), &cid);
	r = conversations_set_msgid(state, msgid, cid);
	CU_ASSERT_EQUAL(r, 0);
    }
    for (i = 0 ; i < N_CID_TO_FOLDER ; i++) {
	gen_cid_folder(i, &cid, &mboxnames);
	conv = conversation_new(state);
	CU_ASSERT_PTR_NOT_NULL(conv);
	for (j = 0 ; j < mboxnames.count ; j++) {
	    conversation_update(state, conv, mboxnames.data[j],
				/*num_records*/1,
				/*exists*/1, /*unseen*/0, NULL,
				/*modseq*/100);
	}
	r = conversation_save(state, cid, conv);
	CU_ASSERT_EQUAL(r, 0);
	conversation_free(conv);
	conv = NULL;
    }

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* open and dump the database */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    conversations_dump(state, fp);

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* do some basic checks on the output file */
    fflush(fp);

    r = fstat(fd, &sb);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT(sb.st_size > 20*N_MSGID_TO_CID + 20*N_CID_TO_FOLDER);

    r = (int)fseek(fp, 0L, SEEK_SET);
    CU_ASSERT_EQUAL(r, 0);

    /* open and truncate the database */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_truncate(state);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* check we can no longer find any of the data */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    for (i = 0 ; i < N_MSGID_TO_CID ; i++) {
	gen_msgid_cid(i, msgid, sizeof(msgid), &cid);
	r = conversations_get_msgid(state, msgid, &cid2);
	CU_ASSERT_EQUAL(r, 0);
	CU_ASSERT_EQUAL(cid2, NULLCONVERSATION);
    }
    for (i = 0 ; i < N_CID_TO_FOLDER ; i++) {
	gen_cid_folder(i, &cid, &mboxnames);
	conv = NULL;
	r = conversation_load(state, cid, &conv);
	CU_ASSERT_EQUAL(r, 0);
	CU_ASSERT_PTR_NULL(conv);
    }

    /* now undump */
    r = conversations_undump(state, fp);
    CU_ASSERT_EQUAL(r, 0);

    r = conversations_commit(&state);
    CU_ASSERT_EQUAL(r, 0);

    /* finally check that we got all the data back */
    r = conversations_open_path(DBNAME, &state);
    CU_ASSERT_EQUAL(r, 0);

    for (i = 0 ; i < N_MSGID_TO_CID ; i++) {
	gen_msgid_cid(i, msgid, sizeof(msgid), &cid);
	r = conversations_get_msgid(state, msgid, &cid2);
	CU_ASSERT_EQUAL(r, 0);
	CU_ASSERT_EQUAL(cid, cid2);
    }
    for (i = 0 ; i < N_CID_TO_FOLDER ; i++) {
	gen_cid_folder(i, &cid, &mboxnames);
	conv = NULL;
	r = conversation_load(state, cid, &conv);
	CU_ASSERT_EQUAL(r, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(conv);
	CU_ASSERT_EQUAL(conv->modseq, 100);
	CU_ASSERT_EQUAL(mboxnames.count, num_folders(conv));
	for (j = 0 ; j < mboxnames.count ; j++) {
	    folder = conversation_find_folder(state, conv, mboxnames.data[j]);
	    CU_ASSERT_PTR_NOT_NULL(folder);
	    CU_ASSERT_EQUAL(folder->modseq, 100);
	}
	conversation_free(conv);
	conv = NULL;
    }

    r = conversations_abort(&state);
    CU_ASSERT_EQUAL(r, 0);

    fclose(fp);
    unlink(filename);
    strarray_fini(&mboxnames);
#undef N_MSGID_TO_CID
#undef N_CID_TO_FOLDER
}


#define TESTCASE(in, exp) \
    { \
	struct buf b = BUF_INITIALIZER; \
	static const char _in[] = in; \
	static const char _exp[] = exp; \
 \
	buf_appendcstr(&b, _in); \
	conversation_normalise_subject(&b); \
	CU_ASSERT_EQUAL(b.len, sizeof(_exp)-1); \
	CU_ASSERT_STRING_EQUAL(b.s, _exp); \
 \
	buf_free(&b); \
    }


static void test_subject_normalise(void)
{
    TESTCASE("understanding merge history",
	     "understandingmergehistory");
    TESTCASE("Re: Alias of constant passed to sub",
	     "Aliasofconstantpassedtosub");
    TESTCASE("Re: RE: Re: Perl_peep recursion exceeds",
	     "Perl_peeprecursionexceeds");
    TESTCASE("Fwd: Re: Sv: Re: SV: vms rename Unix mode fixes",
	     "vmsrenameUnixmodefixes");
    TESTCASE("[PATCH] merging make_ext and make_ext_cross",
	     "mergingmake_extandmake_ext_cross");
    TESTCASE("Re: [PATCH] Parallel testing conflict",
	     "Paralleltestingconflict");
    TESTCASE("Re: [PATCH] Fwd: deprecate UNIVERSAL->import",
	     "deprecateUNIVERSAL->import");
}

#undef TESTCASE


static int set_up(void)
{
    int r;

    r = system("rm -rf " DBDIR);
    if (r)
	return r;

    r = mkdir(DBDIR, 0777);
    if (r < 0) {
	int e = errno;
	perror(DBDIR);
	return e;
    }

    r = mkdir(DBDIR "/db", 0777);
    if (r < 0) {
	int e = errno;
	perror(DBDIR "/db");
	return e;
    }

    libcyrus_config_setstring(CYRUSOPT_CONFIG_DIR, DBDIR);
    cyrusdb_init();
    config_conversations_db = "berkeley";

    return 0;
}

static int tear_down(void)
{
    int r;

    cyrusdb_done();
    config_conversations_db = NULL;

    r = system("rm -rf " DBDIR);
    /* I'm ignoring you */

    return 0;
}