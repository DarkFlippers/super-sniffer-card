/**
 * @file sniffer_card_poller.h
 * @brief One session with a Gen2 Super Sniffer card: activate it and read its trace slots.
 */
#pragma once

#include <nfc/nfc.h>

#include "sniffer_card.h"

/** How the session ended. */
typedef enum {
    SnifferCardPollerResultWaiting, /**< Nothing on the Flipper yet. */
    SnifferCardPollerResultSuccess, /**< Slots were read; the trace count may still be zero. */
    SnifferCardPollerResultNotSniffer, /**< A tag answered, and it is not one of these cards. */
    SnifferCardPollerResultError, /**< The tag went away mid-read, or answered nonsense. */
} SnifferCardPollerResult;

typedef struct SnifferCardPoller SnifferCardPoller;

/** Called from the NFC worker thread once the session has reached a verdict.
 *
 * Runs on that thread, not the GUI's, so a scene's handler must do nothing but post a custom
 * event and read the result back on the other side.
 */
typedef void (*SnifferCardPollerCallback)(void* context);

SnifferCardPoller* sniffer_card_poller_alloc(Nfc* nfc);

void sniffer_card_poller_free(SnifferCardPoller* instance);

/** Begin looking for a card. Keeps looking until a tag answers, or until stopped. */
void sniffer_card_poller_start(
    SnifferCardPoller* instance,
    SnifferCardPollerCallback callback,
    void* context);

void sniffer_card_poller_stop(SnifferCardPoller* instance);

SnifferCardPollerResult sniffer_card_poller_get_result(const SnifferCardPoller* instance);

/** The captures the session read, valid until the next start.
 *
 * @param[out] traces where the array lives; untouched when this returns zero
 * @return how many slots held a real capture
 */
size_t
    sniffer_card_poller_get_traces(const SnifferCardPoller* instance, const SnifferTrace** traces);

/** Slots that answered at all, captures or not.
 *
 * Separate from the trace count so the UI can tell "this is not a sniffer card" from "this is one,
 * and it has not been held against a reader yet".
 */
size_t sniffer_card_poller_get_slots_read(const SnifferCardPoller* instance);
