#include "../sniffer_card_app.h"

void sniffer_card_app_scene_saved_on_enter(void* context) {
    SnifferCardApp* app = context;

    SnifferCardNonceLogResult result = {0};
    const bool saved = sniffer_card_nonce_log_save(app->traces, app->trace_count, &result);

    widget_reset(app->widget);

    if(saved && result.pairs_written == 0) {
        // Everything this card holds is already waiting for MFKey. Said plainly, because these
        // cards keep their captures until a reader overwrites them, so reading one twice is easy
        // to do by accident and would otherwise look like a failure.
        furi_string_printf(
            app->text,
            "%u pair%s already in\nthe MFKey nonce log.\n\nNothing new to add.",
            result.pairs_duplicate,
            result.pairs_duplicate == 1 ? "" : "s");

        widget_add_string_element(
            app->widget, 64, 4, AlignCenter, AlignTop, FontPrimary, "Already saved");
        notification_message(app->notifications, &sequence_success);
    } else if(saved) {
        furi_string_printf(
            app->text,
            // Four lines, which is what fits on a screen with no button row; a fifth runs off the
            // bottom.
            "%u nonce pair%s added\nto the MFKey nonce log.\n\nOpen MFKey to recover.",
            result.pairs_written,
            result.pairs_written == 1 ? "" : "s");

        widget_add_string_element(app->widget, 64, 4, AlignCenter, AlignTop, FontPrimary, "Saved");
        notification_message(app->notifications, &sequence_success);
    } else {
        furi_string_printf(app->text, "Could not write\n" SNIFFER_CARD_NONCE_LOG_PATH);

        widget_add_string_element(
            app->widget, 64, 4, AlignCenter, AlignTop, FontPrimary, "Not saved");
        notification_message(app->notifications, &sequence_error);
    }

    widget_add_string_multiline_element(
        app->widget,
        64,
        SNIFFER_CARD_TEXT_Y,
        AlignCenter,
        AlignTop,
        FontSecondary,
        furi_string_get_cstr(app->text));

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewWidget);
}

bool sniffer_card_app_scene_saved_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    // The nonces are written and the next step is in another app, so there is nothing left to go
    // back through: Back returns to the menu rather than to the result screen and the read screen
    // under it.
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, SnifferCardAppSceneStart);
        return true;
    }

    return false;
}

void sniffer_card_app_scene_saved_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
