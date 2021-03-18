$.controller = {};

$.controller.active_panel = "";
$.controller.panel_inicial = "";


$.controller.activate = function (panel_name) {

    // console.log("cambio old::"+$.controller.active_panel+" new::"+panel_name);
    $($.controller.active_panel).hide();
    $(panel_name).show();
    $.controller.active_panel = panel_name;

};
/**
 * Método para settear el panel inicial
 * @param {*} panel_inicial panel que queramos poner como inicial
 */
$.controller.init = function (panel_inicial) {

    // console.log("Panel inicial="+panel_inicial);

    $('[id^="menu_"]').each(function () {
        var $this = $(this);
        var menu_id = $this.attr('id');
        var panel_id = menu_id.replace('menu_', 'panel_');

        $("#" + menu_id).click(function () {
            $.controller.activate("#" + panel_id);
        });

        // console.log("id_menu::" + menu_id + " id_panel" + panel_id);

    });

    // "Esconde" el div en el que estemos
    $("div.panel").hide();

    // Muestra el panel al que queramos ir (eligiendo en el menú)
    $(panel_inicial).show();
    
    // Activamos el controlador y setteamos con el panel inicial 
    $.controller.active_panel = panel_inicial;
    $.controller.panel_inicial = panel_inicial;

}


$.controller.index = function () {
    $.controller.activate($.controller.panel_inicial);
}
