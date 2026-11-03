#include "../sniffer_card_app.h"

static void sniffer_card_app_scene_read_original_poller_callback(void* context) {
    SnifferCardApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventPollerDone);
}

void sniffer_card_app_scene_read_original_on_enter(void* context) {
    SnifferCardApp* app = context;

    popup_reset(app->popup);
    popup_set_header(app->popup, "Original card", 64, 8, AlignCenter, AlignTop);
    popup_set_text(
        app->popup,
        "Hold the card you want\nthe keys for against\nthe Flipper",
        64,
        24,
        AlignCenter,
        AlignTop);

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewPopup);

    sniffer_card_poller_start(
        app->poller,
        SnifferCardPollerModeReadIdentity,
        sniffer_card_app_scene_read_original_poller_callback,
        app);
}

bool sniffer_card_app_scene_read_original_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    if(event.type != SceneManagerEventTypeCustom) return false;
    if(event.event != SnifferCardAppCustomEventPollerDone) return false;

    // Whatever answered is carried forward, including a tag that is not a Classic at all: the
    // next screen has to show the UID either way, and saying "that is not a Classic" next to the
    // UID it read is more use than refusing here with nothing on screen.
    app->target = *sniffer_card_poller_get_identity(app->poller);
    app->result = sniffer_card_poller_get_result(app->poller);

    notification_message(
        app->notifications,
        sniffer_card_identity_get_type(&app->target) == MfClassicTypeNum ? &sequence_error :
                                                                           &sequence_success);

    scene_manager_next_scene(app->scene_manager, SnifferCardAppSceneConfirmUid);

    return true;
}

void sniffer_card_app_scene_read_original_on_exit(void* context) {
    SnifferCardApp* app = context;

    sniffer_card_poller_stop(app->poller);
    popup_reset(app->popup);
}
