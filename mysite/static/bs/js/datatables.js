// Call the dataTables jQuery plugin
$(document).ready(function() {
  $('#dataTable').DataTable();
});
var t=$('#dataTable').DataTable();
function insert_row(data){
  if(data instanceof Array){
    t.row.add(data).draw(false);
  }
  else{
    let templist=[];
    for(let key in data){
      templist.push(data[key]);
    }
    t.row.add(templist).draw(false);
  }
}
