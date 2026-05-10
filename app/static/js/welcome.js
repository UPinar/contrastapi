(function () {
  'use strict';

  function initCopyKey() {
    document.querySelectorAll('.welcome-container .copy-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var keyEl = document.getElementById('api-key');
        if (!keyEl) return;
        navigator.clipboard.writeText(keyEl.textContent).then(function () {
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(function () {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 2000);
        });
      });
    });
  }

  function initCopyEmail() {
    document.querySelectorAll('[data-copy-email]').forEach(function (el) {
      el.addEventListener('click', function (ev) {
        if (el.tagName === 'A') ev.preventDefault();
        navigator.clipboard.writeText(el.getAttribute('data-copy-email'));
        var orig = el.textContent;
        el.textContent = 'Copied!';
        setTimeout(function () { el.textContent = orig; }, 1500);
      });
    });
  }

  function initPolling() {
    var section = document.getElementById('polling-section');
    if (!section) return;
    var orderId = section.getAttribute('data-order-id');
    var attempts = 0;
    var networkErrors = 0;
    var maxAttempts = 10;
    var interval = 3000;
    var msgEl = document.getElementById('polling-msg');

    function showTimeout() {
      section.classList.add('is-hidden');
      var t = document.getElementById('timeout-section');
      if (t) t.classList.remove('is-hidden');
    }

    function poll() {
      attempts++;
      fetch('/api/check-key?order_id=' + encodeURIComponent(orderId))
        .then(function (r) { return r.json(); })
        .then(function (data) {
          networkErrors = 0;
          if (data.ready) {
            window.location.reload();
          } else if (attempts >= maxAttempts) {
            showTimeout();
          } else {
            setTimeout(poll, interval);
          }
        })
        .catch(function () {
          networkErrors++;
          if (networkErrors >= 3 && msgEl) {
            msgEl.textContent = 'Connection issue. Retrying...';
          }
          if (attempts < maxAttempts) setTimeout(poll, interval);
          else showTimeout();
        });
    }

    setTimeout(poll, interval);
  }

  function init() {
    initCopyKey();
    initCopyEmail();
    initPolling();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
