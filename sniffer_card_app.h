/**
 * @file sniffer_card_app.h
 * @brief Reading a Super Sniffer card's captured authentications off it.
 */
#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/scene_manager.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/popup.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>

#include <nfc/nfc.h>

#include "sniffer_card.h"
#include "sniffer_card_nonce_log.h"
#include "sniffer_card_poller.h"
#include "scenes/scenes.h"

typedef struct {
    Gui* gui;
    NotificationApp* notifications;
    SceneManager* scene_manager;
    ViewDispatcher* view_dispatcher;

    Popup* popup;
    Submenu* submenu;
    Widget* widget;

    // The radio and the session over it. Both outlive every scene: the read scene starts and
    // stops the session, and allocating the Nfc instance per scene would drop the field between
    // a failed read and a retry.
    Nfc* nfc;
    SnifferCardPoller* poller;

    // What the last read came back with, copied out of the poller so the result screen does not
    // depend on the session still being alive. The verdict is part of that copy: the result
    // screen has to tell a tag that is not one of these cards from one that is and has captured
    // nothing yet, and the two differ only in how far the read got.
    SnifferCardPollerResult result;
    SnifferTrace traces[SNIFFER_CARD_TRACE_SLOTS];
    size_t trace_count;
    size_t slots_read;

    // The card the keys are wanted for, read off it rather than typed, and the UID the sniffer
    // card is to be given.
    SnifferCardIdentity target;

    // Text built once on entering a screen and held while that screen draws it: Widget keeps the
    // pointer it is given rather than copying the string.
    FuriString* text;
} SnifferCardApp;

typedef enum {
    SnifferCardAppViewPopup,
    SnifferCardAppViewSubmenu,
    SnifferCardAppViewWidget,
} SnifferCardAppView;

// Submenu item indices travel down the same uint32_t channel as these, so everything here stays
// above any index a submenu in this app can produce.
typedef enum {
    SnifferCardAppCustomEventPollerDone = 100, /**< The NFC session reached a verdict. */
    SnifferCardAppCustomEventSave, /**< Right button on the trace result screen. */
    SnifferCardAppCustomEventRetry,
    SnifferCardAppCustomEventNext, /**< Right button on a screen that only moves forward. */
} SnifferCardAppCustomEvent;

/** Take the result of a finished session out of the poller and into the app. */
void sniffer_card_app_take_result(SnifferCardApp* app);

/** Write a UID out as spaced hex bytes, the way the NFC app shows one. */
void sniffer_card_app_uid_text(const uint8_t* uid, size_t uid_len, FuriString* text);
