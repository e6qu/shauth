// SPDX-License-Identifier: AGPL-3.0-or-later
const root = document.documentElement;
const picture = document.querySelector('#screen-picture');
const image = document.querySelector('#screen-image');
const caption = document.querySelector('#screen-caption');
const controls = document.querySelector('.tour-screen-controls');
const buttons = [...controls.querySelectorAll('button')];
const systemTheme = matchMedia('(prefers-color-scheme: dark)');
const screens = {
  signin: {
    alt: 'Shauth’s sign-in screen, with GitHub sign-in and a local username and password form.',
    title: 'A familiar place to begin.',
    text: 'GitHub and local accounts share one sign-in page. Microsoft Entra ID can also be enabled.',
  },
  signedout: {
    alt: 'Shauth’s signed-out screen, confirming that the Shauth session and connected application sessions have ended.',
    title: 'A clear place to finish.',
    text: 'Shauth confirms when the shared session has ended. App-initiated logout returns to that app’s registered signed-out page.',
  },
};
let selected = 'signin';
function render() {
  const theme = root.dataset.theme === 'system' ? (systemTheme.matches ? 'dark' : 'light') : root.dataset.theme;
  const screen = screens[selected];
  picture.querySelector('source')?.remove();
  image.src = `assets/${selected}-${theme}.png`;
  image.alt = screen.alt;
  const title = document.createElement('strong');
  title.textContent = screen.title;
  caption.replaceChildren(title, document.createTextNode(screen.text));
  for (const button of buttons) button.setAttribute('aria-pressed', String(button.dataset.screen === selected));
}
for (const button of buttons) button.addEventListener('click', () => { selected = button.dataset.screen; render(); });
new MutationObserver(render).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
systemTheme.addEventListener('change', render);
controls.hidden = false;
document.querySelector('#theme-toggle').hidden = false;
caption.setAttribute('aria-live', 'polite');
render();
