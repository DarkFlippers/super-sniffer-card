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

/** Spell out what was read: a verdict, then one line per capture.
 *
 * Each capture carries its tag nonce. Sector, key type and block are not enough to tell two
 * captures apart - a reader working one sector produces a column of identical-looking lines, and
 * on a real card that is the common case rather than a corner one. The nonce is what differs, and
 * printing it is also what shows the list is not repeating itself.
 */
static void sniffer_card_app_scene_read_result_build_text(
    SnifferCardApp* app,
    const SnifferCardNonceLogResult* pairs) {
    if(pairs->pairs_written > 0) {
        furi_string_printf(
            app->text,
            "%u captures, %u new pair%s\n",
            app->trace_count,
            pairs->pairs_written,
            pairs->pairs_written == 1 ? "" : "s");

        if(pairs->pairs_duplicate > 0) {
            furi_string_cat_printf(app->text, "%u more already saved\n", pairs->pairs_duplicate);
        }
    } else if(pairs->pairs_duplicate > 0) {
        // Everything pairable here is already waiting for MFKey. Said as a state rather than as
        // two counts, because "0 new pairs" next to a Save button read as a failure.
        furi_string_printf(
            app->text,
            "%u captures, all %u pair%s\nalready in the log\n",
            app->trace_count,
            pairs->pairs_duplicate,
            pairs->pairs_duplicate == 1 ? "" : "s");
    } else {
        furi_string_printf(app->text, "%u captures, no pairs\n", app->trace_count);
    }

    if(pairs->traces_unpaired > 0) {
        // The one shortfall another tap on the reader fixes: a capture whose key nothing else
        // here shares cannot be cracked, however good it is.
        furi_string_cat_printf(
            app->text, "%u unpaired - needs another\ntap on the reader\n", pairs->traces_unpaired);
    }

    furi_string_cat_str(app->text, "\n");

    for(size_t i = 0; i < app->trace_count; i++) {
        const SnifferTrace* trace = &app->traces[i];
        furi_string_cat_printf(
            app->text,
            "%u Sec%u %c blk%u %08lX\n",
            i + 1,
            sniffer_trace_get_sector(trace),
            trace->key_type == SNIFFER_CARD_AUTH_KEY_A ? 'A' : 'B',
            trace->block,
            trace->nt);
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
        SnifferCardNonceLogResult pairs;
        sniffer_card_nonce_log_count(app->traces, app->trace_count, &pairs);
        sniffer_card_app_scene_read_result_build_text(app, &pairs);

        // Scrollable, because eight captures and their headline do not fit on four lines.
        widget_add_text_scroll_element(
            app->widget, 0, 0, 128, 52, furi_string_get_cstr(app->text));

        // Saving is only offered when there is something to save. With everything already in the
        // log the useful move is the next one, so the button becomes that instead of a Save that
        // would report "nothing new to add" - and when there is nothing to run either, no button
        // is better than one that does nothing.
        if(pairs.pairs_written > 0) {
            widget_add_button_element(
                app->widget,
                GuiButtonTypeRight,
                "Save",
                sniffer_card_app_scene_read_result_button_callback,
                app);
        } else if(pairs.pairs_duplicate > 0 && sniffer_card_app_mfkey_installed()) {
            widget_add_button_element(
                app->widget,
                GuiButtonTypeRight,
                "Run MFKey",
                sniffer_card_app_scene_read_result_button_callback,
                app);
        }
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
        // The same button, labelled for whichever of the two it is: Save when there is something
        // to write, and the handover to MFKey when the log already holds it all.
        SnifferCardNonceLogResult pairs;
        sniffer_card_nonce_log_count(app->traces, app->trace_count, &pairs);

        if(pairs.pairs_written > 0) {
            scene_manager_next_scene(app->scene_manager, SnifferCardAppSceneSaved);
        } else {
            sniffer_card_app_run_mfkey(app);
        }
        return true;
    }

    return false;
}

void sniffer_card_app_scene_read_result_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
