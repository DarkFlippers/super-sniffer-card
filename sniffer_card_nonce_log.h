/**
 * @file sniffer_card_nonce_log.h
 * @brief Handing the captured traces to the MFKey app.
 */
#pragma once

#include "sniffer_card.h"

/** Where the firmware's NFC app keeps the nonces it collects in Detect Reader, and the only file
 * the MFKey app's mfkey32 path reads.
 *
 * Spelled out rather than taken from a header, because `NFC_APP_MFKEY32_LOGS_FILE_PATH` lives in
 * `applications/main/nfc/nfc_app_i.h`, which is firmware-private and not in the FAP SDK. Both
 * sides of that split are checked in this repo's README.
 */
#define SNIFFER_CARD_NONCE_LOG_PATH EXT_PATH("nfc/.mfkey32.log")

/** Most pairs a single card can yield: every capture used, two to a pair. */
#define SNIFFER_CARD_MAX_PAIRS (SNIFFER_CARD_TRACE_SLOTS / 2)

/** What came of writing the nonces out. */
typedef struct {
    size_t pairs_written; /**< Lines appended. */
    size_t pairs_duplicate; /**< Pairs whose key the log already has a pair for. */
    size_t traces_unpaired; /**< Captures with no second capture of the same key. */
} SnifferCardNonceLogResult;

/** Append the usable pairs of traces to the MFKey nonce log.
 *
 * mfkey32 needs two authentications made with the same key, so a lone capture of a sector is
 * useless on its own and is counted into @c traces_unpaired rather than written. Within a group
 * of captures of one key, pairs are taken greedily and disjointly: a key is recovered from any
 * one valid pair, so pairing all combinations would multiply MFKey's work - minutes per line -
 * for no extra keys.
 *
 * A pair is also skipped when the log already holds one for the same card, sector and key type.
 * These cards keep their captures until a reader overwrites them, so reading one twice would
 * otherwise append the same work again, and MFKey's loader does not deduplicate - it runs the
 * full attack per line and only checks the dictionaries for keys it has already found.
 *
 * Opened in append mode, like the firmware's own writer, so nonces from a reader sniffed with
 * the Flipper and nonces from a sniffer card accumulate in the same place.
 *
 * @return false when the log could not be opened or written
 */
bool sniffer_card_nonce_log_save(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result);

/** What sniffer_card_nonce_log_save() would do, without doing it.
 *
 * Reads the log for the duplicate count, so the screen that offers the save can say what saving
 * will actually add.
 */
void sniffer_card_nonce_log_count(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result);
