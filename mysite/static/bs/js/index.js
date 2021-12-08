function add_deliver(data){
    dl=$("#deliver_list");
    element=`<h4 class="small font-weight-bold">${data.name}<spanclass="float-right">20%
    </span></h4>
    <div class="progress mb-4">
        <div class="progress-bar bg-danger" role="progressbar" style="width: ${data.progress}%"
        aria-valuenow="${data.progress}" aria-valuemin="0" aria-valuemax="100"></div>
    </div>`
    dl.append(element);
}
function getFormData($form){
    // var $form = $("#form_data");
    // var data = getFormData($form);
    var unindexed_array = $form.serializeArray();
    var indexed_array = {};

    $.map(unindexed_array, function(n, i){
        indexed_array[n['name']] = n['value'];
    });

    return indexed_array;
}

function store_pri(){
    fileloader=$("#formFile")[0];
    const file = fileloader.files[0];
    const reader = new FileReader();
    reader.onload = function(evt) {
        localStorage.setItem("prikey",evt.target.result);
      };
    reader.readAsText(file);
}