// Arrancamos el controlador
$.controller.init("#panel_inicio");
$('.navbar-nav li a').on('click',function(){
    if (!$(this).hasClass('dropdown-toggle')) {
        $('.navbar-collapse').collapse('hide');
    }
});