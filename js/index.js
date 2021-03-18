// Arrancamos el controlador
$.controller.init("#panel_inicio");
$('.navbar-nav li a').on('click', function () {
    if (!$(this).hasClass('dropdown-toggle')) {
        $('.navbar-collapse').collapse('hide');
    }
});

/**
 * Función para alternar modo oscuro y claro
 */
function myFunction() {
    var element = document.body;
    element.classList.toggle("dark-mode");
}
