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

/** What came of writing the nonces out. */
typedef struct {
    size_t pairs_written; /**< Lines appended, one per usable pair. */
    size_t traces_unpaired; /**< Captures with no second capture of the same key. */
} SnifferCardNonceLogResult;

/** Append every usable pair of traces to the MFKey nonce log.
 *
 * mfkey32 needs two authentications made with the same key, so a lone capture of a sector is
 * useless on its own and is counted into @c traces_unpaired rather than written. Within a group
 * of captures of one key, pairs are taken greedily and disjointly: a key is recovered from any
 * one valid pair, so pairing all combinations would multiply MFKey's work - minutes per line -
 * for no extra keys.
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

/** How many pairs sniffer_card_nonce_log_save() would write, without writing them.
 *
 * Lets the result screen say what is about to happen before the user commits to it.
 */
void sniffer_card_nonce_log_count(
    const SnifferTrace* traces,
    size_t count,
    SnifferCardNonceLogResult* result);
