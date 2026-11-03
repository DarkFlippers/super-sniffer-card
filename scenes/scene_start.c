#include "../sniffer_card_app.h"

// Label, destination and whether it starts the guided run, in one row: the menu used to be a
// list of submenu_add_item() calls dispatched by an if/else chain, where reordering it opened the
// wrong scene and nothing complained.
static const struct {
    const char* label;
    SnifferCardAppScene scene;
    bool guided;
} sniffer_card_start_items[] = {
    {"Recover Keys", SnifferCardAppSceneReadOriginal, true},
    {"Read Sniffer Card", SnifferCardAppSceneRead, false},
    {"Set Sniffer UID", SnifferCardAppSceneReadOriginal, false},
    {"About", SnifferCardAppSceneInfo, false},
};

static void sniffer_card_app_scene_start_callback(void* context, uint32_t index) {
    SnifferCardApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void sniffer_card_app_scene_start_on_enter(void* context) {
    SnifferCardApp* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Sniffer Card");

    for(size_t i = 0; i < COUNT_OF(sniffer_card_start_items); i++) {
        submenu_add_item(
            app->submenu,
            sniffer_card_start_items[i].label,
            i,
            sniffer_card_app_scene_start_callback,
            app);
    }

    submenu_set_selected_item(
        app->submenu, scene_manager_get_scene_state(app->scene_manager, SnifferCardAppSceneStart));

    view_dispatcher_switch_to_view(app->view_dispatcher, SnifferCardAppViewSubmenu);
}

bool sniffer_card_app_scene_start_on_event(void* context, SceneManagerEvent event) {
    SnifferCardApp* app = context;

    if(event.type != SceneManagerEventTypeCustom) return false;
    if(event.event >= COUNT_OF(sniffer_card_start_items)) return false;

    scene_manager_set_scene_state(app->scene_manager, SnifferCardAppSceneStart, event.event);

    // Set here and nowhere else: this is the only screen both runs are entered from, so it is the
    // only place that knows which one was asked for.
    app->guided = sniffer_card_start_items[event.event].guided;

    scene_manager_next_scene(app->scene_manager, sniffer_card_start_items[event.event].scene);

    return true;
}

void sniffer_card_app_scene_start_on_exit(void* context) {
    SnifferCardApp* app = context;
    submenu_reset(app->submenu);
}
