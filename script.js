// function showTime() {
// 	document.getElementById('currentTime').innerHTML = new Date().toUTCString();
// }
// showTime();
// setInterval(function () {
// 	showTime();
// }, 1000);
function showTime() {
  const userInput = window.location.hash.substring(1);
  document.getElementById("currentTime").innerHTML = userInput;
}

showTime();
