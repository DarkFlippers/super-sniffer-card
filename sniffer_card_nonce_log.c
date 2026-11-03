#include "sniffer_card_nonce_log.h"

#include <inttypes.h>
#include <storage/storage.h>
#include <toolbox/stream/buffered_file_stream.h>
#include <toolbox/stream/stream.h>

#define TAG "SnifferCard"

/** One nonce pair, spelled exactly as the firmware's `mfkey32_logger_save_params()` spells it
 * (`applications/main/nfc/helpers/mfkey32_logger.c`).
 *
 * The format matters to the byte: the MFKey app does not parse this with a format string. It
 * checks the line starts with `Sec`, then walks space-separated tokens and takes 5, 7, 9, 11, 13,
 * 15 and 17 as cuid, nt0, nr0, ar0, nt1, nr1 and ar1 (`applications/system/mfkey/init_plugin.c`).
 * Any change to the token count or the spacing silently feeds it the wrong fields.
 */
#define SNIFFER_CARD_NONCE_LOG_FORMAT                                                     \
    "Sec %u key %c cuid %08" PRIx32 " nt0 %08" PRIx32 " nr0 %08" PRIx32 " ar0 %08" PRIx32 \
    " nt1 %08" PRIx32 " nr1 %08" PRIx32 " ar1 %08" PRIx32 "\n"

/** The head of a log line, enough to say which key it is a pair for.
 *
 * SCNx32 rather than PRIx32: the same letter on this target, but this one is read back with
 * sscanf and the two macros are not interchangeable by contract.
 */
#define SNIFFER_CARD_NONCE_LOG_HEAD_FORMAT "Sec %u key %c cuid %8" SCNx32

/** Which key a pair belongs to.
 *
 * The card is part of it: one nonce log accumulates pairs from every card ever read, so a pair
 * for sector 5 key A of one card says nothing about sector 5 key A of another.
 */
typedef struct {
    uint32_t cuid;
    uint8_t sector;
    uint8_t key_type;
} SnifferCardKeyRef;

/** A pair of captures, and whether the log already has this key covered. */
typedef struct {
    const SnifferTrace* a;
    const SnifferTrace* b;
    SnifferCardKeyRef key;
    bool duplicate;
} SnifferCardNoncePair;

static SnifferCardKeyRef sniffer_card_key_ref(const SnifferTrace* trace) {
    return (SnifferCardKeyRef){
        .cuid = sniffer_trace_get_cuid(trace),
        .sector = sniffer_trace_get_sector(trace),
        .key_type = trace->key_type,
    };
}

static bool sniffer_card_key_ref_eq(const SnifferCardKeyRef* a, const SnifferCardKeyRef* b) {
    return a->cuid == b->cuid && a->sector == b->sector && a->key_type == b->key_type;
}

/** Find a capture that can be paired with @p first.
 *
 * Only looks forward: anything before @p first has already had its turn as the left-hand side.
 *
 * Nonces have to differ. Two captures of one key sharing a tag nonce carry the same keystream
 * position, so mfkey32 has nothing to intersect and returns no candidate - it would be a line
 * that costs MFKey minutes and cannot succeed.
 */
static size_t sniffer_card_nonce_log_find_partner(
    const SnifferTrace* traces,
    size_t count,
    const bool* used,
    size_t first) {
    for(size_t i = first + 1; i < count; i++) {
        if(used[i]) continue;
        if(!sniffer_trace_same_key(&traces[first], &traces[i])) continue;
        if(traces[first].nt == traces[i].nt) continue;
        return i;
    }
    return count;
}

/** Pair up the captures, and count the ones left over.
 *
 * @param[out] pairs room for SNIFFER_CARD_MAX_PAIRS
 * @return how many pairs were made
 */
static size_t sniffer_card_nonce_log_collect(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNoncePair* pairs,
    size_t* unpaired) {
    furi_check(count <= SNIFFER_CARD_TRACE_SLOTS);

    bool used[SNIFFER_CARD_TRACE_SLOTS] = {0};
    size_t pair_count = 0;

    *unpaired = 0;

    for(size_t i = 0; i < count; i++) {
        if(used[i]) continue;

        const size_t j = sniffer_card_nonce_log_find_partner(traces, count, used, i);
        if(j == count) {
            (*unpaired)++;
            continue;
        }

        used[i] = true;
        used[j] = true;

        furi_check(pair_count < SNIFFER_CARD_MAX_PAIRS);
        pairs[pair_count++] = (SnifferCardNoncePair){
            .a = &traces[i],
            .b = &traces[j],
            .key = sniffer_card_key_ref(&traces[i]),
            .duplicate = false,
        };
    }

    return pair_count;
}

/** Mark the pairs whose key the log already holds a pair for.
 *
 * Reads the log once and compares against every candidate, rather than building a set of what is
 * in the file: there are at most SNIFFER_CARD_MAX_PAIRS candidates and the file can be long, so
 * the small side is the one worth holding in memory.
 *
 * A log that cannot be read is treated as a log with nothing in it. Writing a duplicate costs
 * MFKey time; refusing to write because the file could not be examined would cost the user their
 * captures, which the card will overwrite.
 */
static void sniffer_card_nonce_log_mark_duplicates(
    Storage* storage,
    SnifferCardNoncePair* pairs,
    size_t pair_count) {
    if(!storage_file_exists(storage, SNIFFER_CARD_NONCE_LOG_PATH)) return;

    Stream* stream = buffered_file_stream_alloc(storage);
    FuriString* line = furi_string_alloc();

    if(buffered_file_stream_open(
           stream, SNIFFER_CARD_NONCE_LOG_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        while(stream_read_line(stream, line)) {
            unsigned int sector = 0;
            char key_letter = 0;
            uint32_t cuid = 0;

            if(sscanf(
                   furi_string_get_cstr(line),
                   SNIFFER_CARD_NONCE_LOG_HEAD_FORMAT,
                   &sector,
                   &key_letter,
                   &cuid) != 3) {
                continue;
            }

            const SnifferCardKeyRef logged = {
                .cuid = cuid,
                .sector = (uint8_t)sector,
                .key_type = key_letter == 'B' ? SNIFFER_CARD_AUTH_KEY_B : SNIFFER_CARD_AUTH_KEY_A,
            };

            for(size_t i = 0; i < pair_count; i++) {
                if(sniffer_card_key_ref_eq(&pairs[i].key, &logged)) pairs[i].duplicate = true;
            }
        }
    } else {
        FURI_LOG_W(TAG, "Cannot read %s, treating it as empty", SNIFFER_CARD_NONCE_LOG_PATH);
    }

    furi_string_free(line);
    buffered_file_stream_close(stream);
    stream_free(stream);
}

static void sniffer_card_nonce_log_format(const SnifferCardNoncePair* pair, FuriString* line) {
    const SnifferTrace* a = pair->a;
    const SnifferTrace* b = pair->b;

    furi_string_printf(
        line,
        SNIFFER_CARD_NONCE_LOG_FORMAT,
        pair->key.sector,
        a->key_type == SNIFFER_CARD_AUTH_KEY_A ? 'A' : 'B',
        pair->key.cuid,
        a->nt,
        a->nr,
        a->ar,
        b->nt,
        b->nr,
        b->ar);
}

/** Pair the captures and check them against the log, without writing anything.
 *
 * Counting and writing share this so they cannot disagree: a screen that promised two pairs and a
 * log that got one would be a bug invisible from either side.
 */
static size_t sniffer_card_nonce_log_prepare(
    Storage* storage,
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNoncePair* pairs,
    SnifferCardNonceLogResult* result) {
    const size_t pair_count =
        sniffer_card_nonce_log_collect(traces, count, pairs, &result->traces_unpaired);

    sniffer_card_nonce_log_mark_duplicates(storage, pairs, pair_count);

    result->pairs_written = 0;
    result->pairs_duplicate = 0;
    for(size_t i = 0; i < pair_count; i++) {
        if(pairs[i].duplicate) {
            result->pairs_duplicate++;
        } else {
            result->pairs_written++;
        }
    }

    return pair_count;
}

void sniffer_card_nonce_log_count(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result) {
    furi_assert(traces);
    furi_assert(result);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    SnifferCardNoncePair pairs[SNIFFER_CARD_MAX_PAIRS];

    sniffer_card_nonce_log_prepare(storage, traces, count, pairs, result);

    furi_record_close(RECORD_STORAGE);
}

bool sniffer_card_nonce_log_save(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result) {
    furi_assert(traces);
    furi_assert(result);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    SnifferCardNoncePair pairs[SNIFFER_CARD_MAX_PAIRS];
    const size_t pair_count =
        sniffer_card_nonce_log_prepare(storage, traces, count, pairs, result);

    Stream* stream = buffered_file_stream_alloc(storage);
    FuriString* line = furi_string_alloc();
    bool saved = false;

    do {
        // Nothing new to add is not a failure: the screen reports it as the duplicate count, and
        // opening the log to write nothing would only risk a write error where there is no write.
        if(result->pairs_written == 0) {
            saved = true;
            break;
        }

        if(!buffered_file_stream_open(
               stream, SNIFFER_CARD_NONCE_LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            FURI_LOG_E(TAG, "Cannot open %s", SNIFFER_CARD_NONCE_LOG_PATH);
            break;
        }

        size_t written = 0;
        for(size_t i = 0; i < pair_count; i++) {
            if(pairs[i].duplicate) continue;

            sniffer_card_nonce_log_format(&pairs[i], line);
            if(stream_write_string(stream, line) != furi_string_size(line)) {
                FURI_LOG_E(TAG, "Cannot write %s", SNIFFER_CARD_NONCE_LOG_PATH);
                break;
            }
            written++;
        }

        if(written != result->pairs_written) {
            // Say what actually reached the file, not what was meant to.
            result->pairs_written = written;
            break;
        }

        saved = true;
    } while(false);

    furi_string_free(line);
    buffered_file_stream_close(stream);
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);

    return saved;
}
