/**
 * JavaScript Functions File
 */
function returnDate()
{
  var currentDate;
  currentDate=new Date();
  var dateString=(currentDate.getMonth()+1)+'/'+currentDate.getDate()+'/'+currentDate.getFullYear();
  return dateString;
}

function returnHour()
{
  var currentDate;
  currentDate=new Date();
  var hourString=currentDate.getHours()+':'+currentDate.getMinutes()+':'+currentDate.getSeconds();
  return hourString; 
}

function javaScriptMessage(){
	return 'This section is generated under JavaScript:<br>';
}

function mainJavascript(){
	document.write(javaScriptMessage())
	document.write('<ul class="listElements">');
	document.write('<li>Current date (dd/mm/yyyy): ' + returnDate());
	document.write('<br>');	
	document.write('<li>Current time (hh:mm:ss): '+returnHour());
	document.write('</ul>');
}