#include "../sniffer_card_app.h"

void sniffer_card_app_scene_saved_on_enter(void* context) {
    SnifferCardApp* app = context;

    SnifferCardNonceLogResult result = {0};
    const bool saved = sniffer_card_nonce_log_save(app->traces, app->trace_count, &result);

    widget_reset(app->widget);

    if(saved) {
        furi_string_printf(
            app->text,
            "%u nonce pair%s added to\nthe MFKey nonce log.\n\nOpen MFKey to recover\nthe keys.",
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
        app->widget, 64, 18, AlignCenter, AlignTop, FontSecondary, furi_string_get_cstr(app->text));

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewWidget);
}

bool sniffer_card_app_scene_saved_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void sniffer_card_app_scene_saved_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
