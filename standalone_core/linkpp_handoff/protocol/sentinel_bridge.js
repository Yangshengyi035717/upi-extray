#!/usr/bin/env node
/**
 * Sentinel bridge prototype for SDK 20260810913b (dual-context parent/frame).
 * stdin JSON: {ua, cores, deviceId, flow, proxy, version, pageUrl,
 *              language, timezone, cookieHeader, sentinelOrigin}
 * stdout JSON: {main, so, error?}
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { spawn } = require("child_process");

const SDK_VERSION = "20260810913b";

function readStdin() {
  return new Promise((resolve) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => (buf += d));
    process.stdin.on("end", () => resolve(buf));
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function makeFetchShim(ua, language, cookieHeader, proxy, pythonBin, tlsImpersonate) {
  // Node/V8 只负责运行 SDK。所有网络请求固定交给当前 Python venv 的
  // curl_cffi，避免 Windows curl.exe (Schannel)、Linux curl (OpenSSL) 与
  // Node/undici 在 TLS、ALPN、HTTP/2 上产生平台漂移。
  const helper = path.join(__dirname, "sentinel_cffi_fetch.py");
  const python = pythonBin || process.env.SENTINEL_PYTHON || process.env.PYTHON_BIN ||
    (process.platform === "win32" ? "python.exe" : "python3");
  return function pythonCurlFetch(url, opts) {
    opts = opts || {};
    return new Promise((resolve, reject) => {
      const headers = Object.assign({}, opts.headers || {});
      headers["user-agent"] = headers["user-agent"] || ua;
      headers["accept"] = headers.accept || "*/*";
      headers["accept-language"] = headers["accept-language"] ||
        `${language},${language.split("-")[0]};q=0.9,en;q=0.8`;
      headers["origin"] = headers.origin || "https://chatgpt.com";
      headers["referer"] = headers.referer || `https://chatgpt.com/backend-api/sentinel/frame.html?sv=${SDK_VERSION}`;
      if (cookieHeader && !headers.cookie) headers.cookie = cookieHeader;

      const child = spawn(python, [helper], { stdio: ["pipe", "pipe", "pipe"] });
      const stdout = [];
      const stderr = [];
      child.stdout.on("data", (c) => stdout.push(c));
      child.stderr.on("data", (c) => stderr.push(c));
      child.on("error", reject);
      child.on("close", (code) => {
        if (code !== 0) {
          reject(new Error(Buffer.concat(stderr).toString("utf8").slice(0, 500) || `sentinel cffi exit ${code}`));
          return;
        }
        try {
          const result = JSON.parse(Buffer.concat(stdout).toString("utf8"));
          if (result.error) {
            reject(new Error(String(result.error).slice(0, 500)));
            return;
          }
          const status = Number(result.status || 0);
          const body = String(result.body || "");
          resolve({
            status,
            ok: status >= 200 && status < 300,
            headers: { get: () => null },
            text: async () => body,
            json: async () => JSON.parse(body),
          });
        } catch (error) {
          reject(error);
        }
      });
      child.stdin.end(JSON.stringify({
        url: String(url),
        method: opts.method || "GET",
        headers,
        body: opts.body == null ? null : String(opts.body),
        proxy,
        timeout: 120,
        tlsImpersonate: tlsImpersonate || "chrome136",
      }));
    });
  };
}

function installEventSystem(win) {
  const listeners = Object.create(null);
  win.addEventListener = function (type, cb) {
    (listeners[type] = listeners[type] || []).push(cb);
  };
  win.removeEventListener = function (type, cb) {
    const arr = listeners[type];
    if (!arr) return;
    const i = arr.indexOf(cb);
    if (i >= 0) arr.splice(i, 1);
  };
  win._dispatch = function (ev) {
    const arr = listeners[ev.type];
    if (!arr) return;
    for (const cb of arr.slice()) {
      try { cb(ev); } catch (e) { /* frame errors surface through timeout paths */ }
    }
  };
}

function baseContext(globals, bootstrapSrc, isFrame) {
  const sandbox = {
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    queueMicrotask,
    fetch: async () => { throw new Error("fetch disabled in this context"); },
    TextEncoder,
    TextDecoder,
    btoa: (s) => Buffer.from(String(s), "latin1").toString("base64"),
    atob: (s) => Buffer.from(String(s), "base64").toString("latin1"),
    crypto: globalThis.crypto,
    URL,
    URLSearchParams,
    __UA__: globals.ua,
    __CORES__: globals.cores,
    __SDK_URL__: globals.sdkUrl,
    __SEED_DID_KEY__: "oai-did",
    __SEED_DID_VAL__: globals.deviceId,
    __PAGE_URL__: isFrame ? globals.frameUrl : globals.pageUrl,
    __LANGUAGE__: globals.language,
    __LANGUAGES__: [globals.language, globals.language.split("-")[0], "en-US"],
    __TIMEZONE__: globals.timezone,
    __COOKIE_HEADER__: globals.cookieHeader,
  };
  vm.createContext(sandbox);
  vm.runInContext(bootstrapSrc, sandbox, { filename: "sentinel_bootstrap.js" });
  installEventSystem(sandbox);
  if (isFrame) {
    sandbox.fetch = globals.fetchShim;
  }
  return sandbox;
}

function loadSDK(sandbox, sdkSrc) {
  vm.runInContext(sdkSrc + "\n;globalThis.__SENTINEL_SDK__ = SentinelSDK;", sandbox, { filename: "sentinel_sdk.js" });
  return sandbox.__SENTINEL_SDK__;
}

function makeIframeElement(frameWin) {
  const loaders = [];
  const el = {
    style: { display: "" },
    tagName: "IFRAME",
    contentWindow: frameWin,
    addEventListener: function (type, cb) {
      if (type === "load") loaders.push(cb);
    },
    removeEventListener: function () {},
    appendChild: function () { return this; },
    remove: function () {},
    getAttribute: function () { return null; },
    setAttribute: function () {},
  };
  el.fireLoad = function () {
    for (const cb of loaders.splice(0)) {
      try { cb({ type: "load" }); } catch (e) {}
    }
  };
  return el;
}

async function main() {
  const raw = await readStdin();
  let args;
  try {
    args = JSON.parse(raw || "{}");
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: "bad args json: " + e.message }));
    return;
  }

  const ua = args.ua || "";
  const cores = args.cores || 16;
  const deviceId = args.deviceId || "";
  const flow = args.flow || "chatgpt_checkout";
  const proxy = args.proxy || "";
  const version = args.version || SDK_VERSION;
  const pageUrl = args.pageUrl || "https://chatgpt.com/";
  const language = args.language || "hi-IN";
  const timezone = args.timezone || "Asia/Kolkata";
  const cookieHeader = args.cookieHeader || "";
  const sentinelOrigin = args.sentinelOrigin || "https://chatgpt.com";
  const pythonBin = args.pythonBin || "";
  const tlsImpersonate = args.tlsImpersonate || "chrome136";
  const frameUrl = `${sentinelOrigin}/backend-api/sentinel/frame.html?sv=${version}`;
  const dir = __dirname;
  const assetsDir = path.join(dir, "sentinel_assets");
  const bootstrapSrc = fs.readFileSync(path.join(assetsDir, "sentinel_bootstrap.js"), "utf8");
  const sdkSrc = fs.readFileSync(path.join(assetsDir, "sentinel_sdk.js"), "utf8");

  const fetchShim = makeFetchShim(
    ua, language, cookieHeader, proxy, pythonBin, tlsImpersonate,
  );

  const globals = {
    ua, cores, deviceId, sdkUrl: `${sentinelOrigin}/sentinel/${version}/sdk.js`,
    pageUrl, frameUrl, language, timezone, cookieHeader, fetchShim,
  };

  // Frame looks like a child of parent; parent looks top-level.
  const parent = baseContext(globals, bootstrapSrc, false);
  const frame = baseContext(globals, bootstrapSrc, true);
  parent.top = parent;
  frame.top = parent;
  frame.parent = parent;

  // Cross-window messaging: parent SDK -> fake iframe -> frame SDK -> parent SDK.
  frame.postMessage = function (data, targetOrigin) {
    frame._dispatch({ type: "message", data, source: parent, origin: sentinelOrigin });
  };
  parent.postMessage = function (data, targetOrigin) {
    parent._dispatch({ type: "message", data, source: frame, origin: sentinelOrigin });
  };

  const iframeEl = makeIframeElement(frame);
  const originalCreateElement = parent.document.createElement.bind(parent.document);
  parent.document.createElement = function (tag) {
    if (String(tag).toLowerCase() === "iframe") {
      return iframeEl;
    }
    return originalCreateElement(tag);
  };
  parent.document.body.appendChild = function (child) {
    if (child === iframeEl) {
      setImmediate(() => iframeEl.fireLoad());
    }
    return child;
  };

  // Load frame first (registers message listener), then parent. Parent SDK
  // creates its hidden iframe during module load, so the fake DOM must be in
  // place before loadSDK(parent).
  const frameSDK = loadSDK(frame, sdkSrc);
  if (!frameSDK || typeof frameSDK.token !== "function") {
    // Frame SDK still registers its message handler even when exports differ.
  }
  const SDK = loadSDK(parent, sdkSrc);

  if (!SDK || typeof SDK.token !== "function") {
    process.stdout.write(JSON.stringify({ error: "sdk.token 未定义" }));
    return;
  }

  const out = { version, hasTokenApi: true };
  const watchdog = setTimeout(() => {
    process.stderr.write("sentinel bridge timeout state=" + JSON.stringify(out) + "\n");
    process.exit(2);
  }, 45000);
  try {
    const mainTok = await SDK.token(flow);
    out.main = String(mainTok || "");
    out.mainRawType = typeof mainTok;
  } catch (e) {
    out.error = "token: " + ((e && e.stack) || e);
    clearTimeout(watchdog);
    process.stdout.write(JSON.stringify(out));
    return;
  }

  // Wait for the SO collector that token() may have started.
  if (!out.error && out.main) {
    for (let i = 0; i < 40; i++) {
      try {
        const soTok = await SDK.sessionObserverToken(flow);
        if (soTok) {
          out.so = String(soTok);
          break;
        }
      } catch (e) {
        out.soErr = ((e && e.message) || e);
        break;
      }
      await sleep(100);
    }
  }

  clearTimeout(watchdog);
  process.stdout.write(JSON.stringify(out), () => {
    setTimeout(() => process.exit(0), 50).unref();
  });
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ error: "fatal: " + ((e && e.stack) || e) }), () => process.exit(1));
});
