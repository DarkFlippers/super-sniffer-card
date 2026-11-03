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
    "Sec %d key %c cuid %08" PRIx32 " nt0 %08" PRIx32 " nr0 %08" PRIx32 " ar0 %08" PRIx32 \
    " nt1 %08" PRIx32 " nr1 %08" PRIx32 " ar1 %08" PRIx32 "\n"

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

/** Walk the captures once, pairing them, and write each pair if there is somewhere to write it.
 *
 * Counting and writing share one function because they have to agree: a result screen that
 * promised three pairs and a log that got two would be a bug nobody could see from either side.
 *
 * @param stream NULL to count without writing
 * @return false only on a write failure
 */
static bool sniffer_card_nonce_log_walk(
    const SnifferTrace* traces,
    size_t count,
    Stream* stream,
    SnifferCardNonceLogResult* result) {
    furi_assert(count <= SNIFFER_CARD_TRACE_SLOTS);

    bool used[SNIFFER_CARD_TRACE_SLOTS] = {0};
    FuriString* line = stream ? furi_string_alloc() : NULL;
    bool success = true;

    result->pairs_written = 0;
    result->traces_unpaired = 0;

    for(size_t i = 0; i < count && success; i++) {
        if(used[i]) continue;

        const size_t j = sniffer_card_nonce_log_find_partner(traces, count, used, i);
        if(j == count) {
            result->traces_unpaired++;
            continue;
        }

        used[i] = true;
        used[j] = true;
        result->pairs_written++;

        if(!stream) continue;

        const SnifferTrace* a = &traces[i];
        const SnifferTrace* b = &traces[j];
        furi_string_printf(
            line,
            SNIFFER_CARD_NONCE_LOG_FORMAT,
            sniffer_trace_get_sector(a),
            a->key_type == SNIFFER_CARD_AUTH_KEY_A ? 'A' : 'B',
            // Both captures carry the same UID, so either will do.
            ((uint32_t)a->cuid[0] << 24) | ((uint32_t)a->cuid[1] << 16) |
                ((uint32_t)a->cuid[2] << 8) | a->cuid[3],
            a->nt,
            a->nr,
            a->ar,
            b->nt,
            b->nr,
            b->ar);

        success = stream_write_string(stream, line) == furi_string_size(line);
    }

    if(line) furi_string_free(line);

    return success;
}

void sniffer_card_nonce_log_count(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result) {
    furi_assert(traces);
    furi_assert(result);

    sniffer_card_nonce_log_walk(traces, count, NULL, result);
}

bool sniffer_card_nonce_log_save(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result) {
    furi_assert(traces);
    furi_assert(result);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    Stream* stream = buffered_file_stream_alloc(storage);
    bool saved = false;

    do {
        if(!buffered_file_stream_open(
               stream, SNIFFER_CARD_NONCE_LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            FURI_LOG_E(TAG, "Cannot open %s", SNIFFER_CARD_NONCE_LOG_PATH);
            break;
        }

        if(!sniffer_card_nonce_log_walk(traces, count, stream, result)) {
            FURI_LOG_E(TAG, "Cannot write %s", SNIFFER_CARD_NONCE_LOG_PATH);
            break;
        }

        saved = true;
    } while(false);

    buffered_file_stream_close(stream);
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);

    return saved;
}
