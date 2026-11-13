(function () {
  'use strict';

  var COPIED = 'Copied';
  var COPY_CMD = 'Copy command';

  function init() {
    // Copy-command buttons
    document.querySelectorAll('.copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var p = btn.previousElementSibling;
        if (!p) return;
        var text = (p.querySelector('code') || p).innerText.replace(/^\$\s+/, '');
        navigator.clipboard.writeText(text).then(function () {
          btn.classList.add('copied');
          btn.setAttribute('aria-label', COPIED);
          setTimeout(function () {
            btn.classList.remove('copied');
            btn.setAttribute('aria-label', COPY_CMD);
          }, 1500);
        });
      });
    });

    // Hamburger nav toggle
    var hamburger = document.querySelector('.hamburger');
    if (hamburger) {
      hamburger.addEventListener('click', function () {
        var open = hamburger.getAttribute('aria-expanded') === 'true';
        hamburger.setAttribute('aria-expanded', String(!open));
        var nav = document.querySelector('.nav-links');
        if (nav) nav.classList.toggle('open');
      });
    }

    // Footer contact click-to-copy
    document.querySelectorAll('a[data-copy-email]').forEach(function (a) {
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        var email = a.getAttribute('data-copy-email');
        navigator.clipboard.writeText(email);
        var orig = a.textContent;
        a.textContent = COPIED;
        setTimeout(function () { a.textContent = orig; }, 1500);
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
