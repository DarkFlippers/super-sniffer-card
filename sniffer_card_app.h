/**
 * @file sniffer_card_app.h
 * @brief Reading a Super Sniffer card's captured authentications off it.
 */
#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/scene_manager.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/byte_input.h>
#include <gui/modules/popup.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <dialogs/dialogs.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>

#include <nfc/nfc.h>

#include "sniffer_card.h"
#include "sniffer_card_nonce_log.h"
#include "sniffer_card_poller.h"
#include "scenes/scenes.h"

/** Top of the button row.
 *
 * elements_button_left/center/right - the three a widget button can draw - all anchor at
 * canvas_height() - 12, so a button box covers rows 52..63. The buttons are drawn after the text,
 * so a line sharing those rows is not clipped, it is painted over.
 */
#define SNIFFER_CARD_BUTTON_ROW_Y 52

/** First body line under a FontPrimary title. */
#define SNIFFER_CARD_TEXT_Y 16

/** Body lines that fit under a title on a screen that also has buttons.
 *
 * FontSecondary steps 11 rows a line, so from SNIFFER_CARD_TEXT_Y the third line ends at 45 and a
 * fourth would start at 49 and run under the button row. Written down because getting it wrong
 * costs a line that is still there, still correct, and invisible.
 */
#define SNIFFER_CARD_TEXT_LINES 3

/** The longest UID these cards come in, and so the longest one that can be set on one. */
#define SNIFFER_CARD_UID_MAX 7

typedef struct {
    Gui* gui;
    DialogsApp* dialogs;
    NotificationApp* notifications;
    SceneManager* scene_manager;
    ViewDispatcher* view_dispatcher;

    ByteInput* byte_input;
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

    // The UID the sniffer card is to be given, however it was come by: read off the card the keys
    // are wanted for, or typed in. A typed one has no SAK, which is why nothing past the confirm
    // screen reads that field - the write checks the sniffer card's own SAK, not the target's.
    SnifferCardIdentity target;

    // Edited in place by the byte input, and deliberately not target.uid: backing out of a
    // half-typed UID must not destroy the one already in hand.
    uint8_t uid_input[SNIFFER_CARD_UID_MAX];
    size_t uid_input_len;

    // Text built once on entering a screen and held while that screen draws it: Widget keeps the
    // pointer it is given rather than copying the string.
    FuriString* text;
} SnifferCardApp;

typedef enum {
    SnifferCardAppViewByteInput,
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
