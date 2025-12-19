
function toggleSection(id) {
const sec = document.getElementById(id);
sec.style.display = sec.style.display === 'block' ? 'none' : 'block';
}

function showPopup() {
document.getElementById('popup').style.display = 'block';
}

function closePopup() {
document.getElementById('popup').style.display = 'none';
}

function filterCommands() {
let input = document.getElementById('search').value.toLowerCase();
let cmds = document.getElementsByClassName('cmd');
for (let i = 0; i < cmds.length; i++) {
cmds[i].style.display = cmds[i].innerText.toLowerCase().includes(input) ? "block" : "none";
}
}
