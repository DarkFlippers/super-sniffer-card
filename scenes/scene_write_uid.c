#include "../sniffer_card_app.h"

static void sniffer_card_app_scene_write_uid_poller_callback(void* context) {
    SnifferCardApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, SnifferCardAppCustomEventPollerDone);
}

void sniffer_card_app_scene_write_uid_on_enter(void* context) {
    SnifferCardApp* app = context;

    popup_reset(app->popup);
    popup_set_header(app->popup, "Setting UID", 64, 8, AlignCenter, AlignTop);
    popup_set_text(
        app->popup,
        "Hold the SNIFFER card\nagainst the Flipper\nuntil it reports back",
        64,
        24,
        AlignCenter,
        AlignTop);

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewPopup);

    // The UID was handed to the poller by the screen before this one, which is the screen that
    // knew which card it came off.
    sniffer_card_poller_start(
        app->poller,
        SnifferCardPollerModeWriteUid,
        sniffer_card_app_scene_write_uid_poller_callback,
        app);
}

bool sniffer_card_app_scene_write_uid_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    if(event.type != SceneManagerEventTypeCustom) return false;
    if(event.event != SnifferCardAppCustomEventPollerDone) return false;

    sniffer_card_app_take_result(app);

    notification_message(
        app->notifications,
        app->result == SnifferCardPollerResultSuccess ? &sequence_success : &sequence_error);

    scene_manager_next_scene(app->scene_manager, SnifferCardAppSceneWriteResult);

    return true;
}

void sniffer_card_app_scene_write_uid_on_exit(void* context) {
    SnifferCardApp* app = context;

    sniffer_card_poller_stop(app->poller);
    popup_reset(app->popup);
}
