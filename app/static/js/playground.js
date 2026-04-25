(function () {
  'use strict';

  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function formatJson(obj, indent) {
    indent = indent || 0;
    var pad = '  '.repeat(indent);
    var padInner = '  '.repeat(indent + 1);

    if (obj === null) return '<span class="bool">null</span>';
    if (typeof obj === 'boolean') return '<span class="bool">' + obj + '</span>';
    if (typeof obj === 'number') return '<span class="num">' + obj + '</span>';
    if (typeof obj === 'string') return '<span class="str">"' + escapeHtml(obj) + '"</span>';

    if (Array.isArray(obj)) {
      if (obj.length === 0) return '[]';
      var items = obj.map(function(v) { return padInner + formatJson(v, indent + 1); });
      return '[\n' + items.join(',\n') + '\n' + pad + ']';
    }

    var keys = Object.keys(obj);
    if (keys.length === 0) return '{}';
    var entries = keys.map(function(k) {
      return padInner + '<span class="key">"' + escapeHtml(k) + '"</span>: ' + formatJson(obj[k], indent + 1);
    });
    return '{\n' + entries.join(',\n') + '\n' + pad + '}';
  }

  var ENDPOINTS = {
    'domain_report': '/v1/domain/',
    'audit': '/v1/audit/',
    'dns': '/v1/dns/',
    'whois': '/v1/whois/',
    'subdomains': '/v1/subdomains/',
    'ssl': '/v1/ssl/',
    'threat': '/v1/threat/',
    'ip': '/v1/ip/',
    'tech': '/v1/tech/',
    'asn': '/v1/asn/',
    'email_mx': '/v1/email/mx/',
    'email_disposable': '/v1/email/disposable/',
    'phone': '/v1/phone/',
    'username': '/v1/username/',
    'archive': '/v1/archive/',
    'scan_headers': '/v1/scan/headers/',
    'cve': '/v1/cve/',
    'cve_search': 'QUERY',
    'bulk_cve': 'POST_BULK_CVE',
    'exploit': '/v1/exploit/',
    'kev': '/v1/kev/',
    'cwe': '/v1/cwe/',
    'threat_report': '/v1/threat-report/',
    'ioc': '/v1/ioc/',
    'bulk_ioc': 'POST_BULK_IOC',
    'hash': '/v1/hash/',
    'password': '/v1/password/',
    'phishing': '/v1/phishing/',
    'check_secrets': 'POST',
    'check_injection': 'POST',
    'check_dependencies': 'POST_DEPS'
  };

  async function run(id) {
    if (!ENDPOINTS[id]) return;
    var btn = document.querySelector('#ep-' + id + ' .btn-run');
    var resp = document.querySelector('#resp-' + id + ' pre');

    var val;
    var url;
    var bulkItems;
    if (id === 'cve_search') {
      var searchParams = {
        limit: document.getElementById('input-cve_search-limit').value.trim() || '5'
      };
      var productVal = document.getElementById('input-cve_search-product').value.trim();
      if (productVal) searchParams.product = productVal;
      var severityVal = document.getElementById('input-cve_search-severity').value;
      if (severityVal) searchParams.severity = severityVal;
      var afterVal = document.getElementById('input-cve_search-published_after').value.trim();
      if (afterVal) searchParams.published_after = afterVal;
      var beforeVal = document.getElementById('input-cve_search-published_before').value.trim();
      if (beforeVal) searchParams.published_before = beforeVal;
      var kevVal = document.getElementById('input-cve_search-kev').value;
      if (kevVal) searchParams.kev = kevVal;
      var epssVal = document.getElementById('input-cve_search-epss_min').value.trim();
      if (epssVal) searchParams.epss_min = epssVal;
      var sortVal = document.getElementById('input-cve_search-sort').value;
      if (sortVal) searchParams.sort = sortVal;
      var offsetVal = document.getElementById('input-cve_search-offset').value.trim();
      if (offsetVal && offsetVal !== '0') searchParams.offset = offsetVal;
      url = '/v1/cves?' + new URLSearchParams(searchParams).toString();
    } else if (ENDPOINTS[id] === 'POST_BULK_CVE' || ENDPOINTS[id] === 'POST_BULK_IOC') {
      var rawBulk = document.getElementById('input-' + id).value.trim();
      if (!rawBulk) {
        resp.innerHTML = '<span class="pg-error">Please enter at least one value</span>';
        return;
      }
      bulkItems = rawBulk.split(/[,\n]+/).map(function(s) { return s.trim(); }).filter(Boolean);
      if (bulkItems.length === 0) {
        resp.innerHTML = '<span class="pg-error">Please enter at least one value</span>';
        return;
      }
      url = ENDPOINTS[id] === 'POST_BULK_CVE' ? '/v1/cves/bulk' : '/v1/iocs/bulk';
    } else if (ENDPOINTS[id] === 'POST') {
      var code = document.getElementById('input-' + id + '-code').value;
      if (!code.trim()) {
        resp.innerHTML = '<span class="pg-error">Please enter code to scan</span>';
        return;
      }
      url = '/v1/' + id.replace('check_', 'check/');
    } else if (ENDPOINTS[id] === 'POST_DEPS') {
      var rawDeps = document.getElementById('input-' + id + '-packages').value.trim();
      if (!rawDeps) {
        resp.innerHTML = '<span class="pg-error">Please enter at least one package</span>';
        return;
      }
      bulkItems = rawDeps.split(/\n+/).map(function(line) {
        var trimmed = line.trim();
        var idx = trimmed.indexOf('==');
        return idx === -1
          ? { name: trimmed, version: null }
          : { name: trimmed.slice(0, idx).trim(), version: trimmed.slice(idx + 2).trim() || null };
      }).filter(function(p) { return p.name; });
      if (bulkItems.length === 0) {
        resp.innerHTML = '<span class="pg-error">Please enter at least one package</span>';
        return;
      }
      url = '/v1/check/dependencies';
    } else {
      var input = document.querySelector('#input-' + id);
      val = input.value.trim();
      if (!val) {
        resp.innerHTML = '<span class="pg-error">Please enter a value</span>';
        return;
      }
      url = ENDPOINTS[id] + encodeURIComponent(val);
    }

    btn.disabled = true;
    btn.textContent = 'Loading...';
    resp.innerHTML = '<span class="pg-loading">Loading...</span>';

    var controller = new AbortController();
    var timer = setTimeout(function() { controller.abort(); }, 15000);

    try {
      var fetchOpts = { signal: controller.signal };
      if (ENDPOINTS[id] === 'POST') {
        fetchOpts.method = 'POST';
        fetchOpts.headers = { 'Content-Type': 'application/json' };
        fetchOpts.body = JSON.stringify({
          code: document.getElementById('input-' + id + '-code').value,
          language: document.getElementById('input-' + id + '-lang').value
        });
      } else if (ENDPOINTS[id] === 'POST_BULK_CVE') {
        fetchOpts.method = 'POST';
        fetchOpts.headers = { 'Content-Type': 'application/json' };
        fetchOpts.body = JSON.stringify({ cve_ids: bulkItems });
      } else if (ENDPOINTS[id] === 'POST_BULK_IOC') {
        fetchOpts.method = 'POST';
        fetchOpts.headers = { 'Content-Type': 'application/json' };
        fetchOpts.body = JSON.stringify({ indicators: bulkItems });
      } else if (ENDPOINTS[id] === 'POST_DEPS') {
        fetchOpts.method = 'POST';
        fetchOpts.headers = { 'Content-Type': 'application/json' };
        fetchOpts.body = JSON.stringify({ packages: bulkItems });
      }
      var res = await fetch(url, fetchOpts);
      clearTimeout(timer);
      var data = await res.json();
      var panel = resp.closest('.pg-response');
      if (!res.ok) {
        resp.innerHTML = '<span class="pg-error">' + escapeHtml(String(data.detail || 'Error ' + res.status)) + '</span>';
        if (panel) panel.dataset.raw = '';
      } else {
        resp.innerHTML = formatJson(data);
        if (panel) panel.dataset.raw = JSON.stringify(data, null, 2);
      }
    } catch (e) {
      clearTimeout(timer);
      resp.innerHTML = '<span class="pg-error">' + (e.name === 'AbortError' ? 'Request timed out' : 'Network error') + '</span>';
      var panelErr = resp.closest('.pg-response');
      if (panelErr) panelErr.dataset.raw = '';
    }

    btn.disabled = false;
    btn.textContent = 'Run \u2192';
  }

  function init() {
    document.querySelectorAll('.btn-run[data-tool]').forEach(function (btn) {
      btn.addEventListener('click', function () { run(btn.getAttribute('data-tool')); });
    });

    document.querySelectorAll('.pg-response').forEach(function (panel) {
      if (panel.querySelector('.pg-copy')) return;

      var scroll = document.createElement('div');
      scroll.className = 'pg-response-scroll';
      while (panel.firstChild) scroll.appendChild(panel.firstChild);
      panel.appendChild(scroll);

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'pg-copy';
      btn.textContent = 'Copy';
      btn.setAttribute('aria-label', 'Copy JSON response to clipboard');
      btn.addEventListener('click', function () {
        var raw = panel.dataset.raw;
        if (!raw) {
          var pre = panel.querySelector('pre');
          raw = pre ? pre.textContent : '';
        }
        if (!raw) return;
        var clip = navigator.clipboard;
        if (!clip || !clip.writeText) {
          btn.textContent = 'Unsupported';
          setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
          return;
        }
        clip.writeText(raw).then(function () {
          btn.textContent = 'Copied!';
          setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
        }).catch(function () {
          btn.textContent = 'Failed';
          setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
        });
      });
      panel.appendChild(btn);
    });

    document.querySelectorAll('.pg-card input, .pg-card textarea, .pg-card select').forEach(function (el) {
      el.addEventListener('input', function () {
        var card = el.closest('.pg-card');
        if (!card) return;
        var panel = card.querySelector('.pg-response');
        if (panel) panel.dataset.raw = '';
      });
    });

    var hamburger = document.querySelector('.hamburger');
    if (hamburger) {
      hamburger.addEventListener('click', function () {
        var open = hamburger.getAttribute('aria-expanded') === 'true';
        hamburger.setAttribute('aria-expanded', String(!open));
        var nav = document.querySelector('.nav-links');
        if (nav) nav.classList.toggle('open');
      });
    }

    document.querySelectorAll('a[data-copy-email]').forEach(function (a) {
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        navigator.clipboard.writeText(a.getAttribute('data-copy-email'));
        var orig = a.textContent;
        a.textContent = 'Copied!';
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
