/* theme-init.js applies the stored theme choice before the first paint.
   Without it the page paints once in the device theme and then jumps.

   Three rules keep it working. A broken one shows no build or test error.
   - Every page loads it in its <head>. A page that forgets it flashes on its own.
   - It stands before the stylesheet links. Below them, the blocking script waits
     for the stylesheets and the page opens late for nothing.
   - It has no defer and no async. Both mean "run after parsing", and the first
     paint then takes the wrong theme.

   The script is a file, not an inline <script>, because the CSP of the pages
   (script-src 'self') forbids inline script. The theme button lives in theme.js. */
(function () {
  'use strict';

  var saved = null;
  try {
    saved = localStorage.getItem('theme');
  } catch (error) {
    /* Storage is blocked (SecurityError), so the device theme applies. This read runs
       on every page load. It stays silent, so a user who blocks site data gets no
       console error on every page. */
  }
  if (saved === 'dark' || saved === 'light') {
    document.documentElement.dataset.theme = saved;
  }
})();
