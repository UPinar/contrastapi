/* theme.js runs the theme button (☾/☀) of the navigation bar.
   theme-init.js has already applied a stored choice before the first paint. This
   file only runs the button. With no stored choice the device theme applies. A
   click stores "light" or "dark" in localStorage under "theme", so the choice
   survives page changes and reloads. */
(function () {
  'use strict';

  var LABEL_TO_LIGHT = 'Switch to light theme';
  var LABEL_TO_DARK = 'Switch to dark theme';
  var DARK_QUERY = '(prefers-color-scheme: dark)';

  var themeBtn = document.getElementById('theme-btn');
  if (!themeBtn) {
    return;
  }

  /* activeTheme is the theme in force: the stored choice, else the device theme. */
  function activeTheme() {
    return document.documentElement.dataset.theme ||
      (window.matchMedia(DARK_QUERY).matches ? 'dark' : 'light');
  }

  /* renderButton shows the theme a click switches to: ☀ while dark. The icon is
     decoration. The aria-label tells a screen reader what the click does. */
  function renderButton() {
    var isDark = activeTheme() === 'dark';
    var label = isDark ? LABEL_TO_LIGHT : LABEL_TO_DARK;
    themeBtn.textContent = isDark ? '☀' : '☾';
    themeBtn.setAttribute('aria-label', label);
    themeBtn.title = label;
  }

  themeBtn.addEventListener('click', function () {
    var next = activeTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem('theme', next);
    } catch (error) {
      /* Storage is blocked or full. The theme still changes on this page, but the
         choice is not kept. */
    }
    renderButton();
  });

  /* With no stored choice the CSS follows a device theme change at once. The button
     follows it too, or it would offer the wrong target after the device switches. */
  window.matchMedia(DARK_QUERY).addEventListener('change', renderButton);

  renderButton();
})();
