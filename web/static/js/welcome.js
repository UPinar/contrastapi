(function () {
  'use strict';

  /* welcome.js claims the Pro key of a paid order. A buyer lands on /welcome with the
     order id in the address. The script sends the id to /api_key_claim and shows the
     key it gets back. It asks again after a 404, for 10 minutes. The server keeps only a
     hash of the key, so the key exists only on this page. The script keeps it nowhere
     else. */

  var CLAIM_PATH = '/api_key_claim';
  var ORDER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  /* NOT_PAID_RETRY_COUNT is how often a 404 is asked again, and NOT_PAID_RETRY_DELAY_MS how
     long each wait is. Together they wait 10 minutes, so an order whose payment event arrives late
     is still claimed. The /api_key_claim row costs 0 credits, so the polls spend none of the
     caller's credits. */
  var NOT_PAID_RETRY_COUNT = 120;
  var NOT_PAID_RETRY_DELAY_MS = 5000;
  var COPIED_RESET_DELAY_MS = 1500;

  var TEXT_NO_ID = 'This page needs the link from your payment receipt.';
  var TEXT_WAITING = 'Waiting for the payment to confirm. This can take a few minutes. Keep this page open.';
  var TEXT_NOT_PAID = 'We have not seen your payment yet. Reload this page in a minute.';
  var TEXT_FAILED = 'Something went wrong. Reload this page in a minute.';
  var TEXT_GONE = 'This key can no longer be claimed.';
  var TEXT_COPY = 'Copy';
  var TEXT_COPIED = 'Copied';

  var statusLine;
  var keyBox;
  var keyField;
  var copyButton;
  var supportLine;
  var orderId = '';
  var notPaidCount = 0;
  var isClaiming = false;

  function showStatus(text) {
    statusLine.textContent = text;
  }

  /* readOrderId reads order_id from the fragment (#order_id=), else from the query
     (?order_id=). A browser does not send the fragment, so an id there reaches no server
     or proxy log. The query form stays readable for a receipt link that still uses it.
     Then the function drops both from the address bar. So the id leaves no trace in the
     history entry once the key is shown. */
  function readOrderId() {
    var value = new URLSearchParams(window.location.hash.slice(1)).get('order_id');
    if (value === null) {
      value = new URLSearchParams(window.location.search).get('order_id');
    }
    if (window.location.search !== '' || window.location.hash !== '') {
      history.replaceState(null, '', window.location.pathname);
    }
    return value === null ? '' : value;
  }

  /* keepOrderIdForReload puts the id back as a fragment. The page then asks the buyer
     to reload, and a reload without the id could not claim the key. */
  function keepOrderIdForReload() {
    history.replaceState(null, '', window.location.pathname + '#order_id=' + orderId);
  }

  function showKey(apiKey) {
    keyField.value = apiKey;
    statusLine.hidden = true;
    keyBox.hidden = false;
  }

  function showGone(message) {
    showStatus(typeof message === 'string' && message !== '' ? message : TEXT_GONE);
    supportLine.hidden = false;
  }

  function showFailed(text) {
    keepOrderIdForReload();
    showStatus(text);
  }

  /* readErrorMessage reads error.message of an error answer, or '' when the body is
     not that shape. */
  function readErrorMessage(response) {
    return response.json().then(function (body) {
      var error = body !== null && typeof body === 'object' ? body.error : null;
      return error !== null && typeof error === 'object' && typeof error.message === 'string' ? error.message : '';
    }, function () {
      return '';
    });
  }

  function handleAnswer(response) {
    if (response.status === 200) {
      return response.json().then(function (body) {
        var apiKey = body !== null && typeof body === 'object' ? body.api_key : null;
        if (typeof apiKey === 'string' && apiKey !== '') {
          showKey(apiKey);
        } else {
          showFailed(TEXT_FAILED);
        }
      });
    }
    if (response.status === 404) {
      if (notPaidCount < NOT_PAID_RETRY_COUNT) {
        notPaidCount++;
        keepOrderIdForReload();
        showStatus(TEXT_WAITING);
        setTimeout(claim, NOT_PAID_RETRY_DELAY_MS);
      } else {
        showFailed(TEXT_NOT_PAID);
      }
      return null;
    }
    if (response.status === 410) {
      return readErrorMessage(response).then(showGone);
    }
    if (response.status === 400) {
      showStatus(TEXT_NO_ID);
      return null;
    }
    showFailed(TEXT_FAILED);
    return null;
  }

  /* claim sends one claim request. isClaiming keeps a second one from starting while
     the first is open. */
  function claim() {
    if (isClaiming) return;
    isClaiming = true;
    fetch(CLAIM_PATH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ order_id: orderId }),
      credentials: 'omit',
      cache: 'no-store'
    }).then(function (response) {
      isClaiming = false;
      return handleAnswer(response);
    }).catch(function () {
      isClaiming = false;
      showFailed(TEXT_FAILED);
    });
  }

  /* copyKey writes the key to the clipboard and leaves the field unselected. Without a
     clipboard, or when the write fails, it selects the key so the buyer can copy it by hand. */
  function copyKey() {
    if (!navigator.clipboard) {
      keyField.select();
      return;
    }
    navigator.clipboard.writeText(keyField.value).then(function () {
      copyButton.textContent = TEXT_COPIED;
      setTimeout(function () { copyButton.textContent = TEXT_COPY; }, COPIED_RESET_DELAY_MS);
    }, function () {
      keyField.select();
    });
  }

  function init() {
    statusLine = document.getElementById('welcome-status');
    keyBox = document.getElementById('welcome-key');
    keyField = document.getElementById('welcome-key-field');
    copyButton = document.getElementById('welcome-copy');
    supportLine = document.getElementById('welcome-support');
    if (!statusLine || !keyBox || !keyField || !copyButton || !supportLine) return;

    copyButton.addEventListener('click', copyKey);
    keyField.addEventListener('focus', function () { keyField.select(); });

    orderId = readOrderId();
    if (!ORDER_ID_PATTERN.test(orderId)) {
      showStatus(TEXT_NO_ID);
      return;
    }
    claim();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
