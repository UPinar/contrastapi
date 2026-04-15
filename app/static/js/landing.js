(function () {
  'use strict';

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
      b.style.cssText = 'background:#1e3a5f;text-align:center;padding:8px;font-size:14px';
      b.innerHTML = '<a href="/cn/" style="color:#93c5fd;text-decoration:none">中文版本可用 — View in Chinese →</a><button style="background:none;border:none;color:#666;margin-left:12px;cursor:pointer;font-size:16px">×</button>';
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
