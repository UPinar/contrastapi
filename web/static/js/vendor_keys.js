(function () {
  'use strict';

  /* vendor_keys.js is the form behind a manage link. A Pro user saves, replaces or
     deletes their own Shodan and AbuseIPDB keys here. The manage link carries the link in
     the address fragment, so the browser never sends it to a server. The script reads the
     link, drops it from the address bar and posts it to /vendor_key_edit in the body.
     A key goes only into that body. The script clears each key field after a send. It
     keeps the link in a variable until the page closes, and keeps no key. */

  var EDIT_PATH = '/vendor_key_edit';
  var LINK_PATTERN = /^[0-9a-f]{64}$/;
  var VENDORS = ['shodan', 'abuseipdb'];
  var VENDOR_NAMES = { shodan: 'Shodan', abuseipdb: 'AbuseIPDB' };
  var DEAD_LINK_CODES = ['link_expired', 'link_invalid'];
  /* KEY_PATTERN is the form the server accepts for each vendor's key, the same rule as
     shodan_isKeyAccepted and abuseipdb_isKeyAccepted. A key in another form is refused
     under its own field before anything is sent. */
  var KEY_PATTERN = {
    shodan: /^[A-Za-z0-9]{1,128}$/,
    abuseipdb: /^[!-~]{1,128}$/
  };
  /* FORMAT_TEXT is the text shown under a vendor's field when its key is not in the form
     KEY_PATTERN describes. */
  var FORMAT_TEXT = {
    shodan: '✘ A Shodan key holds only letters and digits.',
    abuseipdb: '✘ An AbuseIPDB key holds only visible ASCII characters, with no space.'
  };
  /* REFUSAL_TEXT holds the page text of each refusal a user can cause by what they typed.
     Any other refusal shows TEXT_FAILED. */
  var REFUSAL_TEXT = {
    vendor_key_format: '✘ A key does not have the form its vendor uses. Check that you copied the whole key.',
    nothing_to_change: 'Enter a key, or tick a delete box.'
  };

  var TEXT_CHECKING = 'Checking your link…';
  var TEXT_DEAD_LINK = 'This link no longer works. Ask /privacy_my_data for a new one.';
  var TEXT_BUSY = 'Too many requests. Try again later.';
  var TEXT_FAILED = 'Something went wrong. Try again in a minute.';
  var TEXT_VERIFYING = 'Verifying…';
  var TEXT_ALL_DONE = 'Saved. This link is now used. Ask /privacy_my_data for a new link to change again.';
  var TEXT_PLACEHOLDER_SAVED = 'saved, enter a new key to replace';
  var TEXT_PLACEHOLDER_NEW = 'enter a key';

  var STATE_TEXT = {
    working: '✔ saved · working',
    rejected: '✘ saved · rejected, enter a new key',
    vendor_unavailable: '⚠ saved · cannot verify now',
    not_configured: '○ not saved'
  };

  var statusLine;
  var helpBox;
  var form;
  var expiryLine;
  var saveButton;
  var link = '';
  var isSending = false;
  var vendorFields = {};

  function showStatus(text) {
    statusLine.hidden = text === '';
    statusLine.textContent = text;
  }

  /* readLink reads l from the fragment (#l=). A browser does not send the fragment, so
     the link reaches no server or proxy log. The function then drops the fragment and
     the query from the address bar. The link leaves no trace in the history entry. */
  function readLink() {
    var value = new URLSearchParams(window.location.hash.slice(1)).get('l');
    if (window.location.search !== '' || window.location.hash !== '') {
      history.replaceState(null, '', window.location.pathname);
    }
    return value === null ? '' : value;
  }

  /* readErrorCode reads the code of an error answer. The message looks like
     "<code>: <text>", so the code is what stands before the first colon. It returns ''
     when the body has no such message. */
  function readErrorCode(response) {
    return response.json().then(function (body) {
      var error = body !== null && typeof body === 'object' ? body.error : null;
      var message = error !== null && typeof error === 'object' ? error.message : null;
      return typeof message === 'string' ? message.split(':')[0].trim() : '';
    }, function () {
      return '';
    });
  }

  /* post sends one JSON request to the edit endpoint. It sends no credentials and
     takes no cached answer. */
  function post(payload) {
    return fetch(EDIT_PATH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'omit',
      cache: 'no-store'
    });
  }

  function hideForm() {
    form.hidden = true;
    for (var i = 0; i < VENDORS.length; i++) {
      vendorFields[VENDORS[i]].field.value = '';
    }
  }

  function showDeadLink() {
    hideForm();
    showStatus(TEXT_DEAD_LINK);
  }

  /* handleFailure shows the text of a non-200 answer. A dead link hides the form. For
     any other error the form stays, so the user may try again. */
  function handleFailure(response) {
    if (response.status === 429) {
      showStatus(TEXT_BUSY);
      return null;
    }
    if (response.status === 400) {
      return readErrorCode(response).then(function (code) {
        if (DEAD_LINK_CODES.indexOf(code) >= 0) {
          showDeadLink();
        } else if (Object.prototype.hasOwnProperty.call(REFUSAL_TEXT, code)) {
          showStatus(REFUSAL_TEXT[code]);
        } else {
          showStatus(TEXT_FAILED);
        }
      });
    }
    showStatus(TEXT_FAILED);
    return null;
  }

  /* setResult writes the answer to the key just sent, under the vendor's field. An empty
     text hides the line. */
  function setResult(p, text, kind) {
    p.result.hidden = text === '';
    p.result.textContent = text;
    p.result.className = kind === '' ? 'vendor-result' : 'vendor-result ' + kind;
  }

  /* setLine writes a vendor state line and colours it. kind is 'ok', 'bad' or ''. */
  function setLine(p, text, kind) {
    p.state.textContent = text;
    p.state.className = kind === '' ? 'vendor-state' : 'vendor-state ' + kind;
  }

  function updateSaveButton() {
    var any = false;
    for (var i = 0; i < VENDORS.length; i++) {
      var p = vendorFields[VENDORS[i]];
      if (p.field.value !== '' || p.deleteBox.checked) any = true;
    }
    saveButton.disabled = isSending || !any;
  }

  /* showVendorState writes the state line of one vendor. A saved vendor gets the delete
     box and the replace placeholder. A vendor that is not saved has neither box. */
  function showVendorState(vendor, state) {
    var p = vendorFields[vendor];
    var saved = state !== 'not_configured' && Object.prototype.hasOwnProperty.call(STATE_TEXT, state);
    var known = Object.prototype.hasOwnProperty.call(STATE_TEXT, state);
    setLine(p, known ? STATE_TEXT[state] : '', state === 'working' ? 'ok' : (state === 'rejected' ? 'bad' : ''));
    p.deleteLabel.hidden = !saved;
    p.deleteBox.checked = false;
    p.field.placeholder = saved ? TEXT_PLACEHOLDER_SAVED : TEXT_PLACEHOLDER_NEW;
  }

  function showExpiry(seconds) {
    if (typeof seconds !== 'number' || seconds < 0) {
      expiryLine.textContent = '';
      return;
    }
    var minutes = Math.max(1, Math.ceil(seconds / 60));
    expiryLine.textContent = '⏱ This link works for about ' + minutes + (minutes === 1 ? ' more minute.' : ' more minutes.');
  }

  function showForm(body) {
    for (var i = 0; i < VENDORS.length; i++) {
      var entry = body[VENDORS[i]];
      var state = entry !== null && typeof entry === 'object' ? entry.state : '';
      showVendorState(VENDORS[i], state);
    }
    showExpiry(body.expires_in_seconds);
    showStatus('');
    form.hidden = false;
    updateSaveButton();
  }

  function loadStatus() {
    post({ action: 'status', link: link }).then(function (response) {
      if (response.status !== 200) return handleFailure(response);
      return response.json().then(function (body) {
        if (body !== null && typeof body === 'object') {
          showForm(body);
        } else {
          showStatus(TEXT_FAILED);
        }
      });
    }).catch(function () {
      showStatus(TEXT_FAILED);
    });
  }

  /* resultText gives the line a vendor shows after a save. It returns '' for a result
     the script does not know. */
  function resultText(result, retryAfter) {
    if (result === 'saved') return '✔ saved';
    if (result === 'deleted') return '○ not saved';
    if (result === 'unchanged') return 'No change.';
    if (result === 'rejected') return '✘ The vendor refused this key.';
    if (result === 'vendor_unavailable') {
      var wait = typeof retryAfter === 'number' ? ' Try again in ' + retryAfter + ' seconds.' : '';
      return '⚠ Could not verify now, try again.' + wait;
    }
    return '';
  }

  /* showApplyResult shows the answer of one vendor after a save. It returns true when
     the vendor passed: nothing was asked, or the change went through. */
  function showApplyResult(vendor, entry) {
    var p = vendorFields[vendor];
    if (entry === null || typeof entry !== 'object') return true;
    var result = entry.result;
    var kind = result === 'saved' ? 'ok' : (result === 'rejected' || result === 'vendor_unavailable' ? 'bad' : '');
    setResult(p, result === 'unchanged' ? '' : resultText(result, entry.retry_after_seconds), kind);
    if (kind === 'ok') setLine(p, STATE_TEXT.working, 'ok');
    else if (entry.configured === false && result === 'deleted') setLine(p, STATE_TEXT.not_configured, '');
    if (result === 'saved' || result === 'deleted' || result === 'unchanged') {
      p.deleteLabel.hidden = entry.configured !== true;
      p.deleteBox.checked = false;
      p.field.placeholder = entry.configured === true ? TEXT_PLACEHOLDER_SAVED : TEXT_PLACEHOLDER_NEW;
      return true;
    }
    return false;
  }

  function finishApply(body) {
    var allPassed = true;
    for (var i = 0; i < VENDORS.length; i++) {
      var entry = body[VENDORS[i]];
      if (!showApplyResult(VENDORS[i], entry)) allPassed = false;
    }
    if (allPassed) {
      for (var j = 0; j < VENDORS.length; j++) {
        vendorFields[VENDORS[j]].field.disabled = true;
        vendorFields[VENDORS[j]].deleteBox.disabled = true;
      }
      saveButton.disabled = true;
      showStatus(TEXT_ALL_DONE);
    }
  }

  /* buildApply collects only what the user filled or ticked, then clears every key
     field. The keys live in the request body and nowhere else. */
  function buildApply() {
    var payload = { action: 'apply', link: link };
    for (var i = 0; i < VENDORS.length; i++) {
      var p = vendorFields[VENDORS[i]];
      if (p.field.value !== '') payload[VENDORS[i] + '_key'] = p.field.value;
      if (p.deleteBox.checked) payload[VENDORS[i] + '_delete'] = true;
      p.field.value = '';
    }
    return payload;
  }

  /* checkKeyForms refuses, under its own field, each filled key that does not have its
     vendor's form. It returns true when every filled key has it. */
  function checkKeyForms() {
    var allGood = true;
    for (var i = 0; i < VENDORS.length; i++) {
      var p = vendorFields[VENDORS[i]];
      setResult(p, '', '');
      if (p.field.value !== '' && !KEY_PATTERN[VENDORS[i]].test(p.field.value)) {
        setResult(p, FORMAT_TEXT[VENDORS[i]], 'bad');
        allGood = false;
      }
    }
    return allGood;
  }

  function save(event) {
    event.preventDefault();
    if (isSending || saveButton.disabled) return;
    if (!checkKeyForms()) {
      showStatus('');
      return;
    }
    var payload = buildApply();
    isSending = true;
    saveButton.disabled = true;
    showStatus(TEXT_VERIFYING);
    post(payload).then(function (response) {
      isSending = false;
      if (response.status !== 200) return handleFailure(response);
      return response.json().then(function (body) {
        showStatus('');
        if (body !== null && typeof body === 'object') {
          finishApply(body);
        } else {
          showStatus(TEXT_FAILED);
        }
      });
    }).catch(function () {
      isSending = false;
      showStatus(TEXT_FAILED);
    }).then(function () {
      if (!form.hidden && statusLine.textContent !== TEXT_ALL_DONE) updateSaveButton();
    });
  }

  function init() {
    statusLine = document.getElementById('vendor-status');
    helpBox = document.getElementById('vendor-help');
    form = document.getElementById('vendor-form');
    expiryLine = document.getElementById('vendor-expiry');
    saveButton = document.getElementById('vendor-save');
    if (!statusLine || !helpBox || !form || !expiryLine || !saveButton) return;
    for (var i = 0; i < VENDORS.length; i++) {
      var v = VENDORS[i];
      vendorFields[v] = {
        state: document.getElementById('vendor-' + v + '-state'),
        field: document.getElementById('vendor-' + v + '-key'),
        deleteBox: document.getElementById('vendor-' + v + '-delete'),
        deleteLabel: document.getElementById('vendor-' + v + '-delete-label'),
        result: document.getElementById('vendor-' + v + '-result')
      };
      if (!vendorFields[v].state || !vendorFields[v].field || !vendorFields[v].deleteBox || !vendorFields[v].deleteLabel || !vendorFields[v].result) return;
      vendorFields[v].field.addEventListener('input', updateSaveButton);
      vendorFields[v].deleteBox.addEventListener('change', updateSaveButton);
    }
    form.addEventListener('submit', save);

    link = readLink();
    if (!LINK_PATTERN.test(link)) {
      showStatus('');
      helpBox.hidden = false;
      return;
    }
    showStatus(TEXT_CHECKING);
    loadStatus();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
