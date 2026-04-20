// function showTime() {
// 	document.getElementById('currentTime').innerHTML = new Date().toUTCString();
// }
// showTime();
// setInterval(function () {
// 	showTime();
// }, 1000);
function showTime() {
  const userInput = window.location.hash.substring(1);
  if (userInput) {
    document.getElementById("currentTime").innerHTML = userInput;
  }
}

showTime();
console.log("Vulnerable script loaded - CodeQL should detect DOM XSS");
