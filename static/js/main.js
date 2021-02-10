$(document).ready(function() {
    $.noConflict();
    $('.table-sortable').DataTable({
        "pageLength": -1
    });
} );

function eraseCache(){
    confirm("Going back to main page will erase analysis cache. Proceed?");
}