jQuery(document).ready(function($) {
    jQuery.noConflict();
    var table = $('.table-sortable').DataTable({
        "pageLength": -1,
        columnDefs: [
            {type: 'ip-address', targets: 0}
        ]
    });
    
    new $.fn.dataTable.Buttons( table,{
        buttons: [
            {
                text: "Filter On Map",
                action: function (e,dt, node, conf){
                    var tmp = [];
                    $('.odd td:first-child').each(function(){
                        tmp.push(this.innerHTML);
                    });
                    $('.even td:first-child').each(function(){
                        tmp.push(this.innerHTML);
                    });
                    $.ajax('api/refresh-map',
                    {
                        type: 'POST',
                        data: {ip:tmp.toString()},
                        success: function(status){
                           document.getElementById('map-wrapper').contentDocument.location.reload(true);
                           //$('#map-wrapper').attr('src', $('#map-wrapper').attr('src'));
                        }
                    });
                    console.log(tmp);
                }
            },
        ]
    });

    table.buttons(0,null).container().prependTo(
        $('#DataTables_Table_0_filter label')
    );

    var t = Array.from(document.getElementsByTagName("iframe"));
    t.forEach(element => {
        element.contentDocument.location.reload(true);
    });
    var a = document.getElementById("deviation");
    a.src = a.src + "#" + new Date().getTime();
} );

function eraseCache(){
   return confirm("Going back to main page will erase analysis cache. Proceed?");
}