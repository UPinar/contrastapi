(function () {
  'use strict';

  // Anti-FOUC: the inline <style> holds the body hidden (opacity:0) until we add
  // .ready. The stylesheet is render-blocking, so the page is already styled by
  // the time the DOM is parsed — reveal on DOMContentLoaded instead of waiting on
  // webfonts, so a cold cache never lingers on the flat dark background. The CSS
  // animation in the inline <style> is the JS-off failsafe.
  (function () {
    function show() { if (document.body) document.body.classList.add('ready'); }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', show);
    } else {
      show();
    }
  })();

  var isZh = document.documentElement.lang && document.documentElement.lang.toLowerCase().indexOf('zh') === 0;
  var COPIED = isZh ? '已复制' : 'Copied';
  var COPY_CMD = isZh ? '复制命令' : 'Copy command';
  var COPIED_BANG = isZh ? '已复制!' : 'Copied!';

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
        a.textContent = COPIED_BANG;
        setTimeout(function () { a.textContent = orig; }, 1500);
      });
    });

    // ZH redirect banner (English page only)
    if (!isZh && navigator.language && navigator.language.toLowerCase().indexOf('zh') === 0) {
      var b = document.createElement('div');
      b.className = 'zh-banner';
      b.innerHTML = '<a href="/cn/">中文版本可用 — View in Chinese →</a><button>×</button>';
      b.querySelector('button').addEventListener('click', function () { b.remove(); });
      document.body.insertBefore(b, document.body.firstChild);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
