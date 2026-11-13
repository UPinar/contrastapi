(function () {
  'use strict';

  /* crypto_checkout.js opens a NOWPayments invoice when a buyer presses the crypto button, and
     sends the browser to the hosted page. The Content-Security-Policy allows no inline script,
     so the handler lives in this file. */

  var CHECKOUT_PATH = '/crypto_checkout';
  var TEXT_BUSY = 'Creating invoice…';
  var TEXT_FAILED = 'Crypto checkout is unavailable right now. Please try again or pay with a card.';

  var button;
  var errorLine;
  var idleText = '';

  function showFailure() {
    errorLine.textContent = TEXT_FAILED;
    errorLine.hidden = false;
    button.disabled = false;
    button.textContent = idleText;
  }

  function readAnswer(response) {
    if (response.status !== 200) {
      showFailure();
      return null;
    }
    return response.json().then(function (body) {
      var invoiceUrl = body !== null && typeof body === 'object' ? body.invoice_url : null;
      if (typeof invoiceUrl === 'string' && invoiceUrl.indexOf('https://nowpayments.io/') === 0) {
        window.location.href = invoiceUrl;
      } else {
        showFailure();
      }
    });
  }

  /* startCheckout sends one request. The disabled button keeps a second one from starting
     while the first is open, so one press opens one invoice. */
  function startCheckout() {
    idleText = button.textContent;
    errorLine.hidden = true;
    button.disabled = true;
    button.textContent = TEXT_BUSY;
    fetch(CHECKOUT_PATH, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store'
    }).then(readAnswer).catch(showFailure);
  }

  function init() {
    button = document.getElementById('crypto-checkout-btn');
    errorLine = document.getElementById('crypto-checkout-error');
    if (!button || !errorLine) return;
    button.addEventListener('click', startCheckout);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
