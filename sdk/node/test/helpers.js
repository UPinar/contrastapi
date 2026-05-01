"use strict";

// Lightweight HTTP mock layer — replaces global https.request so SDK calls
// are intercepted in-process. No external deps (Jest / nock would force a
// devDependency for ~20 tests; Node's built-in test runner + a hand-rolled
// mock is enough). Keep this file < 100 lines.

const https = require("https");
const http = require("http");
const { Readable } = require("stream");

const _calls = [];
let _routes = [];

function _matchRoute(method, host, path) {
  for (const r of _routes) {
    if (r.method === method && r.host === host && r.path === path) {
      return r;
    }
  }
  return null;
}

function reset() {
  _calls.length = 0;
  _routes = [];
}

function mock(method, url, response) {
  const u = new URL(url);
  _routes.push({
    method: method.toUpperCase(),
    host: u.host,
    path: u.pathname + u.search,
    response,
  });
}

function calls() {
  return _calls.slice();
}

function _fakeRequest(url, options, callback) {
  // Both `https.request(url, opts, cb)` and `https.request(opts, cb)` shapes.
  let urlObj, opts;
  if (typeof url === "string" || url instanceof URL) {
    urlObj = typeof url === "string" ? new URL(url) : url;
    opts = options || {};
  } else {
    urlObj = new URL(`https://${url.host}${url.path || "/"}`);
    opts = url;
    callback = options;
  }
  const method = (opts.method || "GET").toUpperCase();
  const path = urlObj.pathname + urlObj.search;
  const host = urlObj.host;

  // Capture writes so tests can assert request body
  const chunks = [];
  const req = {
    write(chunk) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    },
    end() {
      const body = Buffer.concat(chunks).toString("utf8");
      _calls.push({
        method,
        host,
        path,
        url: `${urlObj.protocol}//${host}${path}`,
        headers: { ...(opts.headers || {}) },
        body,
      });

      const route = _matchRoute(method, host, path);
      if (!route) {
        process.nextTick(() => req.emit("error", new Error(`UNMOCKED: ${method} ${urlObj.href}`)));
        return;
      }

      const resBody = typeof route.response.body === "string"
        ? route.response.body
        : JSON.stringify(route.response.body);
      const res = Readable.from([resBody]);
      res.statusCode = route.response.statusCode || 200;
      res.headers = route.response.headers || { "content-type": "application/json" };
      process.nextTick(() => callback && callback(res));
    },
    on() { return req; },
    setHeader() {},
    destroy() {},
  };
  return req;
}

function install() {
  https.request = _fakeRequest;
  http.request = _fakeRequest;
}

function restore() {
  // Best-effort restore (Node's https.request reference can be re-bound).
  delete require.cache[require.resolve("https")];
  delete require.cache[require.resolve("http")];
}

module.exports = { install, restore, mock, reset, calls };
