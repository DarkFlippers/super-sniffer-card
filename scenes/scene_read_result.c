#include "../sniffer_card_app.h"

static void sniffer_card_app_scene_read_result_button_callback(
    GuiButtonType type,
    InputType input,
    void* context) {
    SnifferCardApp* app = context;

    if(input != InputTypeShort) return;

    if(type == GuiButtonTypeLeft) {
        view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventRetry);
    } else if(type == GuiButtonTypeRight) {
        view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventSave);
    }
}

/** Spell out what was read, one line per capture.
 *
 * The block is shown next to the sector it resolves to rather than instead of it, because the
 * card records the block the reader asked for while the key belongs to the whole sector - and a
 * list showing only sectors would make two captures of one key look like a duplicate line.
 */
static void sniffer_card_app_scene_read_result_build_text(SnifferCardApp* app) {
    SnifferCardNonceLogResult pairs;
    sniffer_card_nonce_log_count(app->traces, app->trace_count, &pairs);

    furi_string_printf(
        app->text,
        "%u capture%s, %u pair%s\n",
        app->trace_count,
        app->trace_count == 1 ? "" : "s",
        pairs.pairs_written,
        pairs.pairs_written == 1 ? "" : "s");

    if(pairs.traces_unpaired > 0) {
        // Worth naming, because it is the one failure the user can fix by doing the same thing
        // again: another tap on the reader turns an unpaired capture into a pair.
        furi_string_cat_printf(
            app->text,
            "%u capture%s with no second\nauth of the same key\n",
            pairs.traces_unpaired,
            pairs.traces_unpaired == 1 ? "" : "s");
    }

    furi_string_cat_str(app->text, "\n");

    for(size_t i = 0; i < app->trace_count; i++) {
        const SnifferTrace* trace = &app->traces[i];
        furi_string_cat_printf(
            app->text,
            "Sec %u key %c  blk %u\n",
            sniffer_trace_get_sector(trace),
            trace->key_type == SNIFFER_CARD_AUTH_KEY_A ? 'A' : 'B',
            trace->block);
    }
}

void sniffer_card_app_scene_read_result_on_enter(void* context) {
    SnifferCardApp* app = context;

    widget_reset(app->widget);

    if(app->result != SnifferCardPollerResultSuccess) {
        widget_add_string_element(
            app->widget, 64, 12, AlignCenter, AlignTop, FontPrimary, "Not a sniffer card");
        widget_add_string_multiline_element(
            app->widget,
            64,
            26,
            AlignCenter,
            AlignTop,
            FontSecondary,
            "This tag does not answer\nan unauthenticated read");
        widget_add_button_element(
            app->widget,
            GuiButtonTypeLeft,
            "Retry",
            sniffer_card_app_scene_read_result_button_callback,
            app);
    } else if(app->trace_count == 0) {
        widget_add_string_element(
            app->widget, 64, 12, AlignCenter, AlignTop, FontPrimary, "Nothing captured");
        widget_add_string_multiline_element(
            app->widget,
            64,
            26,
            AlignCenter,
            AlignTop,
            FontSecondary,
            "Hold the card on a reader\n2-3 times, then read again");
        widget_add_button_element(
            app->widget,
            GuiButtonTypeLeft,
            "Retry",
            sniffer_card_app_scene_read_result_button_callback,
            app);
    } else {
        sniffer_card_app_scene_read_result_build_text(app);
        // Scrollable, because eight captures and their headline do not fit on four lines.
        widget_add_text_scroll_element(
            app->widget, 0, 0, 128, 52, furi_string_get_cstr(app->text));
        widget_add_button_element(
            app->widget,
            GuiButtonTypeRight,
            "Save",
            sniffer_card_app_scene_read_result_button_callback,
            app);
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewWidget);
}

bool sniffer_card_app_scene_read_result_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    // Back leaves for the menu rather than falling into the read screen behind this one. Landing
    // there would silently start another read, which is not what Back means anywhere else - and
    // it would leave the explicit Retry button with nothing of its own to do.
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, SnifferCardAppSceneStart);
        return true;
    }

    if(event.type != SceneManagerEventTypeCustom) return false;

    if(event.event == SnifferCardAppCustomEventRetry) {
        // Back to the read screen rather than forward to another copy of it, so a run of retries
        // does not grow the scene stack.
        scene_manager_previous_scene(app->scene_manager);
        return true;
    }

    if(event.event == SnifferCardAppCustomEventSave) {
        scene_manager_next_scene(app->scene_manager, SnifferCardAppSceneSaved);
        return true;
    }

    return false;
}

void sniffer_card_app_scene_read_result_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
