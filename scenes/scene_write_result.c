#include "../sniffer_card_app.h"

static void sniffer_card_app_scene_write_result_button_callback(
    GuiButtonType type,
    InputType input,
    void* context) {
    SnifferCardApp* app = context;

    if(input != InputTypeShort) return;

    if(type == GuiButtonTypeLeft) {
        view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventRetry);
    } else if(type == GuiButtonTypeRight) {
        view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventNext);
    }
}

/** What to say about each way the write can end.
 *
 * One table rather than a chain of branches, because every row needs the same three decisions -
 * headline, explanation, and whether going on from here makes any sense - and a chain lets one
 * of those go missing for one outcome without anything noticing.
 */
static const struct {
    SnifferCardPollerResult result;
    const char* header;
    const char* text;
    bool can_continue;
} sniffer_card_write_outcomes[] = {
    {SnifferCardPollerResultSuccess, "UID set", NULL, true},
    {SnifferCardPollerResultUidLenMismatch,
     "Wrong card",
     "That sniffer card's UID is\na different length. Use a\n4- or 7-byte card to match.",
     false},
    {SnifferCardPollerResultWriteMismatch,
     "Did not take",
     "The card still answers as\nsomething else. Try again,\nholding it still.",
     false},
    // Worth going on from: the write itself reported success and only the read-back is missing,
    // which is what a card lifted off the Flipper too early looks like. Reading the card is how
    // the user finds out either way, and that is the next screen anyway.
    {SnifferCardPollerResultWriteUnverified,
     "Not confirmed",
     "The card did not come back\nto be checked. It may still\nhave worked.",
     true},
    {SnifferCardPollerResultWrongCard,
     "Not a sniffer card",
     "This tag does not answer\nan unauthenticated read.",
     false},
    {SnifferCardPollerResultError,
     "Failed",
     "The card stopped answering\npart way through.",
     false},
};

void sniffer_card_app_scene_write_result_on_enter(void* context) {
    SnifferCardApp* app = context;

    size_t row = 0;
    while(row < COUNT_OF(sniffer_card_write_outcomes) - 1 &&
          sniffer_card_write_outcomes[row].result != app->result) {
        row++;
    }

    widget_reset(app->widget);
    widget_add_string_element(
        app->widget,
        64,
        2,
        AlignCenter,
        AlignTop,
        FontPrimary,
        sniffer_card_write_outcomes[row].header);

    if(sniffer_card_write_outcomes[row].text) {
        widget_add_string_multiline_element(
            app->widget,
            64,
            17,
            AlignCenter,
            AlignTop,
            FontSecondary,
            sniffer_card_write_outcomes[row].text);
    } else {
        // On success the useful thing to show is the UID the card now answers as, read back off
        // it rather than echoed from what was asked for.
        const SnifferCardIdentity* identity = sniffer_card_poller_get_identity(app->poller);
        sniffer_card_app_uid_text(identity->uid, identity->uid_len, app->text);
        furi_string_cat_str(app->text, "\n\nThe sniffer card now\nanswers as the original");
        widget_add_string_multiline_element(
            app->widget,
            64,
            17,
            AlignCenter,
            AlignTop,
            FontSecondary,
            furi_string_get_cstr(app->text));
    }

    widget_add_button_element(
        app->widget,
        GuiButtonTypeLeft,
        "Retry",
        sniffer_card_app_scene_write_result_button_callback,
        app);

    if(sniffer_card_write_outcomes[row].can_continue) {
        widget_add_button_element(
            app->widget,
            GuiButtonTypeRight,
            app->guided ? "Next" : "Done",
            sniffer_card_app_scene_write_result_button_callback,
            app);
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewWidget);
}

bool sniffer_card_app_scene_write_result_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, SnifferCardAppSceneStart);
        return true;
    }

    if(event.type != SceneManagerEventTypeCustom) return false;

    if(event.event == SnifferCardAppCustomEventRetry) {
        scene_manager_previous_scene(app->scene_manager);
        return true;
    }

    if(event.event == SnifferCardAppCustomEventNext) {
        // Setting the UID on its own ends here. In the guided run it is the halfway point, and
        // what follows happens away from the Flipper.
        if(app->guided) {
            scene_manager_next_scene(app->scene_manager, SnifferCardAppSceneSniffHint);
        } else {
            scene_manager_search_and_switch_to_previous_scene(
                app->scene_manager, SnifferCardAppSceneStart);
        }
        return true;
    }

    return false;
}

void sniffer_card_app_scene_write_result_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
