const dialog = document.querySelector('#error-lookup-dialog');
const input = document.querySelector('#error-lookup-code');
const frame = document.querySelector('#error-lookup-frame');
const status = document.querySelector('#error-lookup-status');
const link = document.querySelector('#error-lookup-link');
let opener;
function lookup() {
  const match = input.value.trim().match(/^(?:AADSTS)?(\d{1,10})$/i);
  if (!match) {
    input.setCustomValidity('Enter digits only, optionally prefixed with AADSTS, such as AADSTS53000.');
    input.reportValidity();
    return;
  }
  const code = String(Number(match[1]));
  input.value = code;
  const url = `https://login.microsoftonline.com/error?code=${code}`;
  link.href = url;
  frame.src = url;
  frame.hidden = false;
  status.textContent = `Microsoft reference for code ${code}. The source page appears below.`;
}
function open(button, code) {
  opener = button;
  input.setCustomValidity('');
  if (!dialog.open) dialog.showModal();
  if (code !== undefined) { input.value = code; lookup(); }
  input.focus();
}
document.querySelector('#error-lookup-open').onclick = event => open(event.currentTarget);
document.querySelector('#error-lookup-close').onclick = () => dialog.close();
dialog.addEventListener('close', () => opener?.focus());
input.oninput = () => input.setCustomValidity('');
document.querySelector('#error-lookup-form').onsubmit = event => { event.preventDefault(); lookup(); };
document.addEventListener('click', event => {
  const button = event.target.closest('[data-error-code]');
  if (button) open(button, button.dataset.errorCode);
});
