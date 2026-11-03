#include "../sniffer_card_app.h"

static void sniffer_card_app_scene_sniff_hint_button_callback(
    GuiButtonType type,
    InputType input,
    void* context) {
    SnifferCardApp* app = context;

    if(input != InputTypeShort || type != GuiButtonTypeRight) return;

    view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventNext);
}

void sniffer_card_app_scene_sniff_hint_on_enter(void* context) {
    SnifferCardApp* app = context;

    widget_reset(app->widget);
    widget_add_string_element(
        app->widget, 64, 2, AlignCenter, AlignTop, FontPrimary, "Now the reader");
    // "At least twice" rather than "twice": a key needs two authentications of that one sector,
    // and a reader does not have to pick the same sector every time it is presented a card.
    widget_add_string_multiline_element(
        app->widget,
        64,
        16,
        AlignCenter,
        AlignTop,
        FontSecondary,
        "Hold the sniffer card on\nthe reader at least twice,\nthen come back and read it");

    widget_add_button_element(
        app->widget,
        GuiButtonTypeRight,
        "Read",
        sniffer_card_app_scene_sniff_hint_button_callback,
        app);

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewWidget);
}

bool sniffer_card_app_scene_sniff_hint_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    // Leaving here is leaving for the reader, which is the whole point of the screen - so Back
    // goes to the menu rather than back into the UID write, and the app can be closed and
    // reopened in between.
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, SnifferCardAppSceneStart);
        return true;
    }

    if(event.type != SceneManagerEventTypeCustom) return false;

    if(event.event == SnifferCardAppCustomEventNext) {
        scene_manager_next_scene(app->scene_manager, SnifferCardAppSceneRead);
        return true;
    }

    return false;
}

void sniffer_card_app_scene_sniff_hint_on_exit(void* context) {
    SnifferCardApp* app = context;
    widget_reset(app->widget);
}
