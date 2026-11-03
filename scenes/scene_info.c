#include "../sniffer_card_app.h"

// A macro rather than a `static const char*`, because clang-format reflows the continuation
// lines of a long concatenated initializer to line up under the `=` and the screen text stops
// being readable in the source.
#define SNIFFER_CARD_INFO_TEXT           \
    "A Super Sniffer card emulates\n"    \
    "a MIFARE Classic and records\n"     \
    "the authentications a reader\n"     \
    "tries against it.\n"                \
    "\n"                                 \
    "Set the card's UID to the one\n"    \
    "you want keys for, hold it on\n"    \
    "the reader 2-3 times, then\n"       \
    "read it here.\n"                    \
    "\n"                                 \
    "This app reads the captures and\n"  \
    "appends them to the MFKey nonce\n"  \
    "log. MFKey recovers the keys and\n" \
    "writes them to the user\n"          \
    "dictionary.\n"                      \
    "\n"                                 \
    "Two captures of one key are\n"      \
    "needed to recover it, so tap the\n" \
    "reader more than once.\n"           \
    "\n"                                 \
    "Supported: Gen2 cards, the ones\n"  \
    "that answer a plain 30 xx read.\n"  \
    "The Gen1 and Furui revisions are\n" \
    "not read yet."

void sniffer_card_app_scene_info_on_enter(void* context) {
    SnifferCardApp* app = context;

    widget_reset(app->widget);
    widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, SNIFFER_CARD_INFO_TEXT);

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewWidget);
}

bool sniffer_card_app_scene_info_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void sniffer_card_app_scene_info_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
