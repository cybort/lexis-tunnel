// src/agent/frame.ts
import { createHash, randomBytes as randomBytes4 } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect as connectTcp, createServer as createTcp, isIP } from "node:net";
import { connect as connectTls, createServer as createTls } from "node:tls";
import { isMainThread, parentPort, Worker } from "node:worker_threads";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// node_modules/@bokuweb/zstd-wasm/dist/esm/zstd.js
var Module = typeof Module !== "undefined" ? Module : {};
var moduleOverrides = {};
var key;
for (key in Module) {
  if (Module.hasOwnProperty(key)) {
    moduleOverrides[key] = Module[key];
  }
}
var arguments_ = [];
var err = Module["printErr"] || console.warn.bind(console);
for (key in moduleOverrides) {
  if (moduleOverrides.hasOwnProperty(key)) {
    Module[key] = moduleOverrides[key];
  }
}
var quit_ = (status, toThrow) => {
  throw toThrow;
};
moduleOverrides = null;
if (Module["arguments"])
  arguments_ = Module["arguments"];
if (Module["thisProgram"])
  thisProgram = Module["thisProgram"];
if (Module["quit"])
  quit_ = Module["quit"];
if (typeof WebAssembly !== "object") {
  abort("no native wasm support detected");
}
var wasmMemory;
var ABORT = false;
var EXITSTATUS;
var HEAPU8;
var HEAP8;
function updateMemoryViews() {
  var b = wasmMemory.buffer;
  Module["HEAP8"] = HEAP8 = new Int8Array(b);
  Module["HEAPU8"] = HEAPU8 = new Uint8Array(b);
}
var __ATPRERUN__ = [];
var __ATINIT__ = [];
var __ATPOSTRUN__ = [];
var runtimeInitialized = false;
function preRun() {
  if (Module["preRun"]) {
    if (typeof Module["preRun"] == "function")
      Module["preRun"] = [Module["preRun"]];
    while (Module["preRun"].length) {
      addOnPreRun(Module["preRun"].shift());
    }
  }
  callRuntimeCallbacks(__ATPRERUN__);
}
function initRuntime() {
  runtimeInitialized = true;
  callRuntimeCallbacks(__ATINIT__);
}
function postRun() {
  if (Module["postRun"]) {
    if (typeof Module["postRun"] == "function")
      Module["postRun"] = [Module["postRun"]];
    while (Module["postRun"].length) {
      addOnPostRun(Module["postRun"].shift());
    }
  }
  callRuntimeCallbacks(__ATPOSTRUN__);
}
function addOnPreRun(cb) {
  __ATPRERUN__.unshift(cb);
}
function addOnInit(cb) {
  __ATINIT__.unshift(cb);
}
function addOnPostRun(cb) {
  __ATPOSTRUN__.unshift(cb);
}
var runDependencies = 0;
var dependenciesFulfilled = null;
function addRunDependency(id) {
  var _a;
  runDependencies++;
  (_a = Module["monitorRunDependencies"]) === null || _a === void 0 ? void 0 : _a.call(Module, runDependencies);
}
function removeRunDependency(id) {
  var _a;
  runDependencies--;
  (_a = Module["monitorRunDependencies"]) === null || _a === void 0 ? void 0 : _a.call(Module, runDependencies);
  if (runDependencies == 0) {
    if (dependenciesFulfilled) {
      var callback = dependenciesFulfilled;
      dependenciesFulfilled = null;
      callback();
    }
  }
}
function abort(what) {
  var _a;
  (_a = Module["onAbort"]) === null || _a === void 0 ? void 0 : _a.call(Module, what);
  what = "Aborted(" + what + ")";
  err(what);
  ABORT = true;
  what += ". Build with -sASSERTIONS for more info.";
  var e = new WebAssembly.RuntimeError(what);
  throw e;
}
function getWasmImports() {
  return { a: wasmImports };
}
function getBinaryPromise(url) {
  return fetch(url, { credentials: "same-origin" }).then(function(response) {
    if (!response["ok"]) {
      throw "failed to load wasm binary file at '" + url + "'";
    }
    return response["arrayBuffer"]();
  });
}
function init(filePathOrBuf) {
  var info = getWasmImports();
  function receiveInstance(instance, module) {
    wasmExports = instance.exports;
    wasmMemory = wasmExports["f"];
    updateMemoryViews();
    addOnInit(wasmExports["g"]);
    removeRunDependency("wasm-instantiate");
    return wasmExports;
  }
  addRunDependency("wasm-instantiate");
  function receiveInstantiationResult(result) {
    receiveInstance(result["instance"]);
  }
  function instantiateArrayBuffer(receiver) {
    return getBinaryPromise(filePathOrBuf).then(function(binary) {
      var result = WebAssembly.instantiate(binary, info);
      return result;
    }).then(receiver, function(reason) {
      err("failed to asynchronously prepare wasm: " + reason);
      abort(reason);
    });
  }
  function instantiateAsync() {
    if (filePathOrBuf && filePathOrBuf.byteLength > 0) {
      return WebAssembly.instantiate(filePathOrBuf, info).then(receiveInstantiationResult, function(reason) {
        err("wasm compile failed: " + reason);
      });
    } else if (typeof WebAssembly.instantiateStreaming === "function" && typeof filePathOrBuf === "string" && typeof fetch === "function") {
      return fetch(filePathOrBuf, { credentials: "same-origin" }).then(function(response) {
        var result = WebAssembly.instantiateStreaming(response, info);
        return result.then(receiveInstantiationResult, function(reason) {
          err("wasm streaming compile failed: " + reason);
          err("falling back to ArrayBuffer instantiation");
          return instantiateArrayBuffer(receiveInstantiationResult);
        });
      });
    } else {
      return instantiateArrayBuffer(receiveInstantiationResult);
    }
  }
  if (Module["instantiateWasm"]) {
    try {
      var exports = Module["instantiateWasm"](info, receiveInstance);
      return exports;
    } catch (e) {
      err("Module.instantiateWasm callback failed with error: " + e);
      return false;
    }
  }
  instantiateAsync();
  return {};
}
var ExitStatus = class {
  constructor(status) {
    this.name = "ExitStatus";
    this.message = `Program terminated with exit(${status})`;
    this.status = status;
  }
};
var callRuntimeCallbacks = (callbacks) => {
  while (callbacks.length > 0) {
    callbacks.shift()(Module);
  }
};
var noExitRuntime = Module["noExitRuntime"] || true;
var __abort_js = () => abort("");
var runtimeKeepaliveCounter = 0;
var __emscripten_runtime_keepalive_clear = () => {
  noExitRuntime = false;
  runtimeKeepaliveCounter = 0;
};
var timers = {};
var handleException = (e) => {
  if (e instanceof ExitStatus || e == "unwind") {
    return EXITSTATUS;
  }
  quit_(1, e);
};
var keepRuntimeAlive = () => noExitRuntime || runtimeKeepaliveCounter > 0;
var _proc_exit = (code) => {
  var _a;
  EXITSTATUS = code;
  if (!keepRuntimeAlive()) {
    (_a = Module["onExit"]) === null || _a === void 0 ? void 0 : _a.call(Module, code);
    ABORT = true;
  }
  quit_(code, new ExitStatus(code));
};
var exitJS = (status, implicit) => {
  EXITSTATUS = status;
  _proc_exit(status);
};
var _exit = exitJS;
var maybeExit = () => {
  if (!keepRuntimeAlive()) {
    try {
      _exit(EXITSTATUS);
    } catch (e) {
      handleException(e);
    }
  }
};
var callUserCallback = (func) => {
  if (ABORT) {
    return;
  }
  try {
    func();
    maybeExit();
  } catch (e) {
    handleException(e);
  }
};
var _emscripten_get_now = () => performance.now();
var __setitimer_js = (which, timeout_ms) => {
  if (timers[which]) {
    clearTimeout(timers[which].id);
    delete timers[which];
  }
  if (!timeout_ms)
    return 0;
  var id = setTimeout(() => {
    delete timers[which];
    callUserCallback(() => __emscripten_timeout(which, _emscripten_get_now()));
  }, timeout_ms);
  timers[which] = { id, timeout_ms };
  return 0;
};
var getHeapMax = () => 2147483648;
var alignMemory = (size, alignment) => Math.ceil(size / alignment) * alignment;
var growMemory = (size) => {
  var b = wasmMemory.buffer;
  var pages = (size - b.byteLength + 65535) / 65536 | 0;
  try {
    wasmMemory.grow(pages);
    updateMemoryViews();
    return 1;
  } catch (e) {
  }
};
var _emscripten_resize_heap = (requestedSize) => {
  var oldSize = HEAPU8.length;
  requestedSize >>>= 0;
  var maxHeapSize = getHeapMax();
  if (requestedSize > maxHeapSize) {
    return false;
  }
  for (var cutDown = 1; cutDown <= 4; cutDown *= 2) {
    var overGrownHeapSize = oldSize * (1 + 0.2 / cutDown);
    overGrownHeapSize = Math.min(overGrownHeapSize, requestedSize + 100663296);
    var newSize = Math.min(maxHeapSize, alignMemory(Math.max(requestedSize, overGrownHeapSize), 65536));
    var replacement = growMemory(newSize);
    if (replacement) {
      return true;
    }
  }
  return false;
};
var wasmImports = {
  c: __abort_js,
  b: __emscripten_runtime_keepalive_clear,
  d: __setitimer_js,
  e: _emscripten_resize_heap,
  a: _proc_exit
};
var wasmExports;
var _ZSTD_isError = Module["_ZSTD_isError"] = (a0) => (_ZSTD_isError = Module["_ZSTD_isError"] = wasmExports["h"])(a0);
var _ZSTD_compressBound = Module["_ZSTD_compressBound"] = (a0) => (_ZSTD_compressBound = Module["_ZSTD_compressBound"] = wasmExports["i"])(a0);
var _ZSTD_createCCtx = Module["_ZSTD_createCCtx"] = () => (_ZSTD_createCCtx = Module["_ZSTD_createCCtx"] = wasmExports["j"])();
var _ZSTD_freeCCtx = Module["_ZSTD_freeCCtx"] = (a0) => (_ZSTD_freeCCtx = Module["_ZSTD_freeCCtx"] = wasmExports["k"])(a0);
var _ZSTD_compress_usingDict = Module["_ZSTD_compress_usingDict"] = (a0, a1, a2, a3, a4, a5, a6, a7) => (_ZSTD_compress_usingDict = Module["_ZSTD_compress_usingDict"] = wasmExports["l"])(a0, a1, a2, a3, a4, a5, a6, a7);
var _ZSTD_compress = Module["_ZSTD_compress"] = (a0, a1, a2, a3, a4) => (_ZSTD_compress = Module["_ZSTD_compress"] = wasmExports["m"])(a0, a1, a2, a3, a4);
var _ZSTD_createDCtx = Module["_ZSTD_createDCtx"] = () => (_ZSTD_createDCtx = Module["_ZSTD_createDCtx"] = wasmExports["n"])();
var _ZSTD_freeDCtx = Module["_ZSTD_freeDCtx"] = (a0) => (_ZSTD_freeDCtx = Module["_ZSTD_freeDCtx"] = wasmExports["o"])(a0);
var _ZSTD_getFrameContentSize = Module["_ZSTD_getFrameContentSize"] = (a0, a1) => (_ZSTD_getFrameContentSize = Module["_ZSTD_getFrameContentSize"] = wasmExports["p"])(a0, a1);
var _ZSTD_decompress_usingDict = Module["_ZSTD_decompress_usingDict"] = (a0, a1, a2, a3, a4, a5, a6) => (_ZSTD_decompress_usingDict = Module["_ZSTD_decompress_usingDict"] = wasmExports["q"])(a0, a1, a2, a3, a4, a5, a6);
var _ZSTD_decompress = Module["_ZSTD_decompress"] = (a0, a1, a2, a3) => (_ZSTD_decompress = Module["_ZSTD_decompress"] = wasmExports["r"])(a0, a1, a2, a3);
var _malloc = Module["_malloc"] = (a0) => (_malloc = Module["_malloc"] = wasmExports["s"])(a0);
var _free = Module["_free"] = (a0) => (_free = Module["_free"] = wasmExports["t"])(a0);
var __emscripten_timeout = (a0, a1) => (__emscripten_timeout = wasmExports["v"])(a0, a1);
var calledRun;
dependenciesFulfilled = function runCaller() {
  if (!calledRun)
    run();
  if (!calledRun)
    dependenciesFulfilled = runCaller;
};
function run() {
  if (runDependencies > 0) {
    return;
  }
  preRun();
  if (runDependencies > 0) {
    return;
  }
  function doRun() {
    var _a;
    if (calledRun)
      return;
    calledRun = true;
    Module["calledRun"] = true;
    if (ABORT)
      return;
    initRuntime();
    (_a = Module["onRuntimeInitialized"]) === null || _a === void 0 ? void 0 : _a.call(Module);
    postRun();
  }
  if (Module["setStatus"]) {
    Module["setStatus"]("Running...");
    setTimeout(() => {
      setTimeout(() => Module["setStatus"](""), 1);
      doRun();
    }, 1);
  } else {
    doRun();
  }
}
Module["run"] = run;
if (Module["preInit"]) {
  if (typeof Module["preInit"] == "function")
    Module["preInit"] = [Module["preInit"]];
  while (Module["preInit"].length > 0) {
    Module["preInit"].pop()();
  }
}
Module["init"] = init;

// node_modules/@bokuweb/zstd-wasm/dist/esm/module.js
var __awaiter = function(thisArg, _arguments, P2, generator) {
  function adopt(value) {
    return value instanceof P2 ? value : new P2(function(resolve) {
      resolve(value);
    });
  }
  return new (P2 || (P2 = Promise))(function(resolve, reject) {
    function fulfilled(value) {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    }
    function rejected(value) {
      try {
        step(generator["throw"](value));
      } catch (e) {
        reject(e);
      }
    }
    function step(result) {
      result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
    }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
};
var initialized = (() => new Promise((resolve) => {
  Module.onRuntimeInitialized = resolve;
}))();
var waitInitialized = () => __awaiter(void 0, void 0, void 0, function* () {
  yield initialized;
});

// node_modules/@bokuweb/zstd-wasm/dist/esm/errors/index.js
var isError = (code) => {
  const _isError = Module["_ZSTD_isError"];
  return _isError(code);
};

// node_modules/@bokuweb/zstd-wasm/dist/esm/simple/compress.js
var compressBound = (size) => {
  const bound = Module["_ZSTD_compressBound"];
  return bound(size);
};
var compress = (buf2, level) => {
  const bound = compressBound(buf2.byteLength);
  const malloc = Module["_malloc"];
  const compressed = malloc(bound);
  const src = malloc(buf2.byteLength);
  Module.HEAP8.set(buf2, src);
  const free = Module["_free"];
  try {
    const _compress = Module["_ZSTD_compress"];
    const sizeOrError = _compress(compressed, bound, src, buf2.byteLength, level !== null && level !== void 0 ? level : 3);
    if (isError(sizeOrError)) {
      throw new Error(`Failed to compress with code ${sizeOrError}`);
    }
    const data = new Uint8Array(Module.HEAPU8.buffer, compressed, sizeOrError).slice();
    free(compressed, bound);
    free(src, buf2.byteLength);
    return data;
  } catch (e) {
    free(compressed, bound);
    free(src, buf2.byteLength);
    throw e;
  }
};

// node_modules/@bokuweb/zstd-wasm/dist/esm/simple/decompress.js
var getFrameContentSize = (src, size) => {
  const getSize = Module["_ZSTD_getFrameContentSize"];
  return getSize(src, size);
};
var decompress = (buf2, opts = { defaultHeapSize: 1024 * 1024 }) => {
  const malloc = Module["_malloc"];
  const src = malloc(buf2.byteLength);
  Module.HEAP8.set(buf2, src);
  const contentSize = getFrameContentSize(src, buf2.byteLength);
  const size = contentSize === -1 ? opts.defaultHeapSize : contentSize;
  const free = Module["_free"];
  const heap = malloc(size);
  try {
    const _decompress = Module["_ZSTD_decompress"];
    const sizeOrError = _decompress(heap, size, src, buf2.byteLength);
    if (isError(sizeOrError)) {
      throw new Error(`Failed to compress with code ${sizeOrError}`);
    }
    const data = new Uint8Array(Module.HEAPU8.buffer, heap, sizeOrError).slice();
    free(heap, size);
    free(src, buf2.byteLength);
    return data;
  } catch (e) {
    free(heap, size);
    free(src, buf2.byteLength);
    throw e;
  }
};

// src/lib/lexis/bytes.ts
function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function utf8(s) {
  return new TextEncoder().encode(s);
}
function fromUtf8(b) {
  return new TextDecoder("utf-8", { fatal: false }).decode(b);
}
function u16be(n) {
  return new Uint8Array([n >> 8 & 255, n & 255]);
}
function u32be(n) {
  return new Uint8Array([n >>> 24 & 255, n >>> 16 & 255, n >>> 8 & 255, n & 255]);
}
function readU16(b, o) {
  return (b[o] << 8 | b[o + 1]) >>> 0;
}
function readU32(b, o) {
  return (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
}
function hex(b, max) {
  const v = max === void 0 ? b : b.subarray(0, max);
  let s = "";
  for (let i = 0; i < v.length; i++) s += v[i].toString(16).padStart(2, "0");
  return s;
}
function b64(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function bytesToChunks(data) {
  const out = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < data.length; i++) {
    acc = acc << 8 | data[i];
    bits += 8;
    while (bits >= 12) {
      bits -= 12;
      out.push(acc >> bits & 4095);
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0) out.push(acc << 12 - bits & 4095);
  return out;
}
function chunksToBytes(chunks) {
  const tmp = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < chunks.length; i++) {
    acc = acc << 12 | chunks[i] & 4095;
    bits += 12;
    while (bits >= 8) {
      bits -= 8;
      tmp.push(acc >> bits & 255);
      acc &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(tmp);
}

// src/lib/lexis/crypto.ts
var ECDH = { name: "ECDH", namedCurve: "P-256" };
var HKDF_CAP = 8e3;
function buf(data) {
  const out = new ArrayBuffer(data.byteLength);
  new Uint8Array(out).set(data);
  return out;
}
function asBytes(data) {
  const view = new Uint8Array(data);
  const out = new Uint8Array(view.length);
  out.set(view);
  return out;
}
var LexisError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "LexisError";
  }
};
async function sha256(data) {
  return asBytes(await crypto.subtle.digest("SHA-256", buf(data)));
}
async function fingerprintOf(raw) {
  const d = await sha256(raw);
  const h = hex(d.subarray(0, 8));
  return (h.match(/.{1,4}/g) ?? [h]).join("-");
}
async function createIdentity() {
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const fingerprint = await fingerprintOf(publicRaw);
  return { publicJwk, privateJwk, publicRaw, fingerprint };
}
async function importPrivateJwk(jwk) {
  return crypto.subtle.importKey("jwk", jwk, ECDH, true, ["deriveBits"]);
}
async function importRawPublic(raw) {
  return crypto.subtle.importKey("raw", buf(raw), ECDH, true, []);
}
async function ecdh(priv, pub) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  return asBytes(bits);
}
async function hkdf(ikm, salt, info, bytes) {
  const base = await crypto.subtle.importKey("raw", buf(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(info) },
    base,
    bytes * 8
  );
  return asBytes(bits);
}
async function hkdfStream(ikm, salt, infoLabel, nbytes) {
  const parts = [];
  let left = nbytes;
  let i = 0;
  while (left > 0) {
    const n = Math.min(HKDF_CAP, left);
    parts.push(await hkdf(ikm, salt, concat(utf8(infoLabel), u32be(i)), n));
    left -= n;
    i += 1;
  }
  return concat(...parts);
}
async function hmac(key2, data) {
  const k = await crypto.subtle.importKey(
    "raw",
    buf(key2),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return asBytes(await crypto.subtle.sign("HMAC", k, buf(data)));
}
function assertPoint(raw, label) {
  if (raw.length !== 65 || raw[0] !== 4) {
    throw new LexisError(`${label}\u516C\u94A5\u4E0D\u662F P-256 \u672A\u538B\u7F29\u70B9`);
  }
}
async function identityFromJwks(publicJwk, privateJwk) {
  if (publicJwk.kty !== "EC" || publicJwk.crv !== "P-256") {
    throw new LexisError("\u4FA7\u8F66\u91CC\u7684\u516C\u94A5\u4E0D\u662F P-256");
  }
  if (privateJwk.x && publicJwk.x && privateJwk.x !== publicJwk.x) {
    throw new LexisError("\u4FA7\u8F66\u91CC\u7684\u79C1\u94A5\u548C\u516C\u94A5\u4E0D\u662F\u4E00\u5BF9");
  }
  const pub = await crypto.subtle.importKey("jwk", publicJwk, ECDH, true, []);
  await importPrivateJwk(privateJwk);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pub));
  const fingerprint = await fingerprintOf(publicRaw);
  return { publicJwk, privateJwk, publicRaw, fingerprint };
}

// src/lib/lexis/spec.ts
var SPEC = {
  name: "lexis-codebook-ctr-v1",
  curve: "P-256",
  kdf: "Argon2id",
  expand: "HKDF-SHA-256",
  mac: "HMAC-SHA-256",
  macBytes: 16,
  lexiconSize: 4096,
  bitsPerWord: 12,
  windowSec: 300,
  /** Accept the previous window this many seconds in, and the next window this many seconds before the roll. */
  skewSec: 120,
  counterBits: 24
};
var GLUE = ["the", "our", "its", "that", "and"];
var GLUE_SET = new Set(GLUE);
var LEADS = ["the", "our", "its", "that"];

// src/lib/lexis/lexicon.ts
var ONSETS = [
  "b",
  "c",
  "d",
  "f",
  "g",
  "h",
  "j",
  "k",
  "l",
  "m",
  "n",
  "p",
  "r",
  "s",
  "t",
  "v",
  "w",
  "z",
  "bl",
  "br",
  "ch",
  "cl",
  "cr",
  "dr",
  "fl",
  "fr",
  "gl",
  "gr",
  "pl",
  "pr",
  "sc",
  "sh",
  "sk",
  "sl",
  "sm",
  "sn",
  "sp",
  "st",
  "sw",
  "th",
  "tr",
  "tw",
  "wh",
  "qu"
];
var NUCLEI = [
  "a",
  "e",
  "i",
  "o",
  "u",
  "ae",
  "ai",
  "au",
  "ea",
  "ee",
  "ia",
  "ie",
  "io",
  "oa",
  "oe",
  "oo",
  "ou"
];
var CODAS = [
  "d",
  "k",
  "l",
  "m",
  "n",
  "p",
  "r",
  "s",
  "t",
  "x",
  "ld",
  "ll",
  "nd",
  "nt",
  "rd",
  "rn",
  "sh",
  "st",
  "th"
];
var SPACE = ONSETS.length * NUCLEI.length * CODAS.length;
function wordFromIndex(n) {
  const coda = n % CODAS.length;
  const nucleus = Math.floor(n / CODAS.length) % NUCLEI.length;
  const onset = Math.floor(n / (CODAS.length * NUCLEI.length));
  return ONSETS[onset] + NUCLEI[nucleus] + CODAS[coda];
}
async function buildLexicon(seed) {
  if (SPACE < SPEC.lexiconSize || SPACE >= 65536) {
    throw new Error("\u97F3\u8282\u7A7A\u95F4\u5C3A\u5BF8\u4E0D\u5BF9");
  }
  const used = new Uint8Array(SPACE);
  const seen = /* @__PURE__ */ new Set();
  const words = [];
  const limit = Math.floor(65536 / SPACE) * SPACE;
  let round = 0;
  let pool = new Uint8Array(0);
  let pos = 0;
  const pull = async () => {
    pool = await hkdfStream(seed, utf8(`LEXIS-LEX-STREAM-${round}`), "idx", 16e3);
    round += 1;
    pos = 0;
  };
  const next16 = async () => {
    if (pos + 2 > pool.length) await pull();
    const v = pool[pos] << 8 | pool[pos + 1];
    pos += 2;
    return v;
  };
  let guard = 0;
  while (words.length < SPEC.lexiconSize) {
    if (guard++ > SPACE * 4) throw new Error("\u8BCD\u8868\u751F\u6210\u5931\u8D25");
    let draw = await next16();
    while (draw >= limit) draw = await next16();
    const n = draw % SPACE;
    if (used[n]) continue;
    used[n] = 1;
    const w = wordFromIndex(n);
    if (w.length < 3 || GLUE_SET.has(w) || seen.has(w)) continue;
    seen.add(w);
    words.push(w);
  }
  return words;
}
var staticCache = null;
function staticLexicon() {
  if (!staticCache) {
    staticCache = (async () => {
      const seed = await sha256(utf8("LEXIS-STATIC-ALPHABET-v1"));
      return buildLexicon(seed);
    })();
  }
  return staticCache;
}
var lexiconCache = /* @__PURE__ */ new Map();
function cacheId(key2, window) {
  let hex2 = `${window}:`;
  for (const b of key2) hex2 += b.toString(16).padStart(2, "0");
  return hex2;
}
async function sessionLexicon(sessionKey, window) {
  const id = cacheId(sessionKey, window);
  const hit = lexiconCache.get(id);
  if (hit) return hit;
  const pending = (async () => {
    const seed = await hkdfStream(sessionKey, utf8("LEXIS-LEX-SALT"), `win-${window}`, 32);
    return buildLexicon(seed);
  })();
  lexiconCache.set(id, pending);
  if (lexiconCache.size > 32) {
    const oldest = lexiconCache.keys().next().value;
    if (oldest !== void 0) lexiconCache.delete(oldest);
  }
  return pending;
}
function invertLexicon(words) {
  const map = /* @__PURE__ */ new Map();
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (map.has(w)) throw new Error(`\u8BCD\u8868\u6709\u91CD\u590D\u8BCD ${w}`);
    map.set(w, i);
  }
  if (map.size !== SPEC.lexiconSize) throw new Error("\u8BCD\u8868\u957F\u5EA6\u4E0D\u5BF9");
  return map;
}

// src/lib/lexis/codec.ts
function dress(words, counter) {
  const parts = [];
  for (let i = 0; i < words.length; i += 4) {
    const group = words.slice(i, i + 4);
    const head = i === 0 ? LEADS[counter & 3] : "and";
    parts.push(`${head} ${group.join(" ")}.`);
  }
  return parts.join(" ");
}
function undress(prose) {
  return prose.trim().toLowerCase().replace(/[.]/g, " ").split(/\s+/).filter((w) => w.length > 0 && !GLUE_SET.has(w));
}
async function encodeStatic(data) {
  const lex = await staticLexicon();
  const framed = concat(u16be(data.length), data);
  const words = bytesToChunks(framed).map((c) => {
    if (c < 0 || c >= SPEC.lexiconSize) throw new Error("\u9759\u6001\u7F16\u7801\u8D8A\u754C");
    return lex[c];
  });
  return dress(words, 0);
}
async function decodeStatic(prose) {
  const lex = await staticLexicon();
  const inverse = /* @__PURE__ */ new Map();
  for (let i = 0; i < lex.length; i++) inverse.set(lex[i], i);
  const chunks = [];
  for (const w of undress(prose)) {
    const idx = inverse.get(w);
    if (idx === void 0) throw new Error(`\u63E1\u624B\u8BCD\u4E0D\u5728\u9759\u6001\u8BCD\u8868\u91CC\uFF1A${w}`);
    chunks.push(idx);
  }
  const raw = chunksToBytes(chunks);
  if (raw.length < 2) throw new Error("\u63E1\u624B\u62A5\u6587\u8FC7\u77ED");
  const len = readU16(raw, 0);
  if (raw.length < 2 + len) throw new Error("\u63E1\u624B\u62A5\u6587\u88AB\u622A\u65AD");
  return raw.slice(2, 2 + len);
}

// node_modules/@noble/curves/node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function anumber(n, title = "") {
  if (typeof n !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(`${prefix}expected number, got ${typeof n}`);
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
  }
}
function abytes(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new TypeError("Hash must wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
  if (h.outputLen < 1)
    throw new Error('"outputLen" must be >= 1');
  if (h.blockLen < 1)
    throw new Error('"blockLen" must be >= 1');
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new RangeError('"digestInto() output" expected to be of length >=' + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex2 = "";
  for (let i = 0; i < bytes.length; i++) {
    hex2 += hexes[bytes[i]];
  }
  return hex2;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex2) {
  if (typeof hex2 !== "string")
    throw new TypeError("hex string expected, got " + typeof hex2);
  if (hasHexBuiltin) {
    try {
      return Uint8Array.fromHex(hex2);
    } catch (error) {
      if (error instanceof SyntaxError)
        throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex2.length;
  const al = hl / 2;
  if (hl % 2)
    throw new RangeError("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex2.charCodeAt(hi));
    const n2 = asciiToBase16(hex2.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex2[hi] + hex2[hi + 1];
      throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function createHasher(hashCons, info = {}) {
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes2(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/curves/node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE2) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen must be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to ||= new this.constructor();
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// node_modules/@noble/curves/node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  constructor(outputLen) {
    super(64, outputLen, 8, false);
  }
  get() {
    const { A, B, C, D, E, F, G: G2, H } = this;
    return [A, B, C, D, E, F, G2, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G2, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G2 | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G: G2, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G2;
      G2 = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G2 = G2 + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G2, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  A = SHA256_IV[0] | 0;
  B = SHA256_IV[1] | 0;
  C = SHA256_IV[2] | 0;
  D = SHA256_IV[3] | 0;
  E = SHA256_IV[4] | 0;
  F = SHA256_IV[5] | 0;
  G = SHA256_IV[6] | 0;
  H = SHA256_IV[7] | 0;
  constructor() {
    super(32);
  }
};
var sha2562 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// node_modules/@noble/curves/utils.js
var abytes2 = (value, length, title) => abytes(value, length, title);
var anumber2 = anumber;
var bytesToHex2 = bytesToHex;
var concatBytes2 = (...arrays) => concatBytes(...arrays);
var hexToBytes2 = (hex2) => hexToBytes(hex2);
var isBytes2 = isBytes;
var randomBytes3 = (bytesLength) => randomBytes2(bytesLength);
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
function abool(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}
function abignumber(n) {
  if (typeof n === "bigint") {
    if (!isPosBig(n))
      throw new RangeError("positive bigint expected, got " + n);
  } else
    anumber2(n);
  return n;
}
function asafenumber(value, title = "") {
  if (typeof value !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected number, got type=" + typeof value);
  }
  if (!Number.isSafeInteger(value)) {
    const prefix = title && `"${title}" `;
    throw new RangeError(prefix + "expected safe integer, got " + value);
  }
}
function numberToHexUnpadded(num) {
  const hex2 = abignumber(num).toString(16);
  return hex2.length & 1 ? "0" + hex2 : hex2;
}
function hexToNumber(hex2) {
  if (typeof hex2 !== "string")
    throw new TypeError("hex string expected, got " + typeof hex2);
  return hex2 === "" ? _0n : BigInt("0x" + hex2);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
}
function numberToBytesBE(n, len) {
  anumber(len);
  if (len === 0)
    throw new RangeError("zero length");
  n = abignumber(n);
  const hex2 = n.toString(16);
  if (hex2.length > len * 2)
    throw new RangeError("number too large");
  return hexToBytes(hex2.padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes2(bytes));
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new RangeError("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  if (n < _0n)
    throw new Error("expected non-negative bigint, got " + n);
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
var bitMask = (n) => (_1n << BigInt(n)) - _1n;
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  anumber(hashLen, "hashLen");
  anumber(qByteLen, "qByteLen");
  if (typeof hmacFn !== "function")
    throw new TypeError("hmacFn must be a function");
  const u8n = (len) => new Uint8Array(len);
  const NULL = Uint8Array.of();
  const byte0 = Uint8Array.of(0);
  const byte1 = Uint8Array.of(1);
  const _maxDrbgIters = 1e3;
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...msgs) => hmacFn(k, concatBytes2(v, ...msgs));
  const reseed = (seed = NULL) => {
    k = h(byte0, seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(byte1, seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= _maxDrbgIters)
      throw new Error("drbg: tried max amount of iterations");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = void 0;
    while ((res = pred(gen())) === void 0)
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
function validateObject(object, fields = {}, optFields = {}) {
  if (Object.prototype.toString.call(object) !== "[object Object]")
    throw new TypeError("expected valid options object");
  function checkField(fieldName, expectedType, isOpt) {
    if (!isOpt && expectedType !== "function" && !Object.hasOwn(object, fieldName))
      throw new TypeError(`param "${fieldName}" is invalid: expected own property`);
    const val = object[fieldName];
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new TypeError(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
  }
  const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
  iter(fields, false);
  iter(optFields, true);
}

// node_modules/@noble/curves/abstract/modular.js
var _0n2 = /* @__PURE__ */ BigInt(0);
var _1n2 = /* @__PURE__ */ BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
  if (b <= _0n2)
    throw new Error("mod: expected positive modulus, got " + b);
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function assertIsSquare(Fp, root, n) {
  const F = Fp;
  if (!F.eql(F.sqr(root), n))
    throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp, n) {
  const F = Fp;
  const p1div4 = (F.ORDER + _1n2) / _4n;
  const root = F.pow(n, p1div4);
  assertIsSquare(F, root, n);
  return root;
}
function sqrt5mod8(Fp, n) {
  const F = Fp;
  const p5div8 = (F.ORDER - _5n) / _8n;
  const n2 = F.mul(n, _2n);
  const v = F.pow(n2, p5div8);
  const nv = F.mul(n, v);
  const i = F.mul(F.mul(nv, _2n), v);
  const root = F.mul(nv, F.sub(i, F.ONE));
  assertIsSquare(F, root, n);
  return root;
}
function sqrt9mod16(P2) {
  const Fp_ = Field(P2);
  const tn = tonelliShanks(P2);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P2 + _7n) / _16n;
  return ((Fp, n) => {
    const F = Fp;
    let tv1 = F.pow(n, c4);
    let tv2 = F.mul(tv1, c1);
    const tv3 = F.mul(tv1, c2);
    const tv4 = F.mul(tv1, c3);
    const e1 = F.eql(F.sqr(tv2), n);
    const e2 = F.eql(F.sqr(tv3), n);
    tv1 = F.cmov(tv1, tv2, e1);
    tv2 = F.cmov(tv4, tv3, e2);
    const e3 = F.eql(F.sqr(tv2), n);
    const root = F.cmov(tv1, tv2, e3);
    assertIsSquare(F, root, n);
    return root;
  });
}
function tonelliShanks(P2) {
  if (P2 < _3n)
    throw new Error("sqrt is not defined for small field");
  let Q = P2 - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P2);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp, n) {
    const F = Fp;
    if (F.is0(n))
      return n;
    if (FpLegendre(F, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = F.mul(F.ONE, cc);
    let t = F.pow(n, Q);
    let R = F.pow(n, Q1div2);
    while (!F.eql(t, F.ONE)) {
      if (F.is0(t))
        return F.ZERO;
      let i = 1;
      let t_tmp = F.sqr(t);
      while (!F.eql(t_tmp, F.ONE)) {
        i++;
        t_tmp = F.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = F.pow(c, exponent);
      M = i;
      c = F.sqr(b);
      t = F.mul(t, c);
      R = F.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P2) {
  if (P2 % _4n === _3n)
    return sqrt3mod4;
  if (P2 % _8n === _5n)
    return sqrt5mod8;
  if (P2 % _16n === _9n)
    return sqrt9mod16(P2);
  return tonelliShanks(P2);
}
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    BYTES: "number",
    BITS: "number"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  validateObject(field, opts);
  asafenumber(field.BYTES, "BYTES");
  asafenumber(field.BITS, "BITS");
  if (field.BYTES < 1 || field.BITS < 1)
    throw new Error("invalid field: expected BYTES/BITS > 0");
  if (field.ORDER <= _1n2)
    throw new Error("invalid field: expected ORDER > 1, got " + field.ORDER);
  return field;
}
function FpPow(Fp, num, power) {
  const F = Fp;
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return F.ONE;
  if (power === _1n2)
    return num;
  let p = F.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = F.mul(p, d);
    d = F.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(Fp, nums, passZero = false) {
  const F = Fp;
  const inverted = new Array(nums.length).fill(passZero ? F.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (F.is0(num))
      return acc;
    inverted[i] = acc;
    return F.mul(acc, num);
  }, F.ONE);
  const invertedAcc = F.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (F.is0(num))
      return acc;
    inverted[i] = F.mul(acc, inverted[i]);
    return F.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp, n) {
  const F = Fp;
  const p1mod2 = (F.ORDER - _1n2) / _2n;
  const powered = F.pow(n, p1mod2);
  const yes = F.eql(powered, F.ONE);
  const zero = F.eql(powered, F.ZERO);
  const no = F.eql(powered, F.neg(F.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber2(nBitLength);
  if (n <= _0n2)
    throw new Error("invalid n length: expected positive n, got " + n);
  if (nBitLength !== void 0 && nBitLength < 1)
    throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
  const bits = bitLen(n);
  if (nBitLength !== void 0 && nBitLength < bits)
    throw new Error(`invalid n length: expected bit length (${bits}) >= n.length (${nBitLength})`);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
var FIELD_SQRT = /* @__PURE__ */ new WeakMap();
var _Field = class {
  ORDER;
  BITS;
  BYTES;
  isLE;
  ZERO = _0n2;
  ONE = _1n2;
  _lengths;
  _mod;
  constructor(ORDER, opts = {}) {
    if (ORDER <= _1n2)
      throw new Error("invalid field: expected ORDER > 1, got " + ORDER);
    let _nbitLength = void 0;
    this.isLE = false;
    if (opts != null && typeof opts === "object") {
      if (typeof opts.BITS === "number")
        _nbitLength = opts.BITS;
      if (typeof opts.sqrt === "function")
        Object.defineProperty(this, "sqrt", { value: opts.sqrt, enumerable: true });
      if (typeof opts.isLE === "boolean")
        this.isLE = opts.isLE;
      if (opts.allowedLengths)
        this._lengths = Object.freeze(opts.allowedLengths.slice());
      if (typeof opts.modFromBytes === "boolean")
        this._mod = opts.modFromBytes;
    }
    const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
    if (nByteLength > 2048)
      throw new Error("invalid field: expected ORDER of <= 2048 bytes");
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    Object.freeze(this);
  }
  create(num) {
    return mod(num, this.ORDER);
  }
  isValid(num) {
    if (typeof num !== "bigint")
      throw new TypeError("invalid field element: expected bigint, got " + typeof num);
    return _0n2 <= num && num < this.ORDER;
  }
  is0(num) {
    return num === _0n2;
  }
  // is valid and invertible
  isValidNot0(num) {
    return !this.is0(num) && this.isValid(num);
  }
  isOdd(num) {
    return (num & _1n2) === _1n2;
  }
  neg(num) {
    return mod(-num, this.ORDER);
  }
  eql(lhs, rhs) {
    return lhs === rhs;
  }
  sqr(num) {
    return mod(num * num, this.ORDER);
  }
  add(lhs, rhs) {
    return mod(lhs + rhs, this.ORDER);
  }
  sub(lhs, rhs) {
    return mod(lhs - rhs, this.ORDER);
  }
  mul(lhs, rhs) {
    return mod(lhs * rhs, this.ORDER);
  }
  pow(num, power) {
    return FpPow(this, num, power);
  }
  div(lhs, rhs) {
    return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
  }
  // Same as above, but doesn't normalize
  sqrN(num) {
    return num * num;
  }
  addN(lhs, rhs) {
    return lhs + rhs;
  }
  subN(lhs, rhs) {
    return lhs - rhs;
  }
  mulN(lhs, rhs) {
    return lhs * rhs;
  }
  inv(num) {
    return invert(num, this.ORDER);
  }
  sqrt(num) {
    let sqrt = FIELD_SQRT.get(this);
    if (!sqrt)
      FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
    return sqrt(this, num);
  }
  toBytes(num) {
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }
  fromBytes(bytes, skipValidation = false) {
    abytes2(bytes);
    const { _lengths: allowedLengths, BYTES, isLE: isLE2, ORDER, _mod: modFromBytes } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
    let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (modFromBytes)
      scalar = mod(scalar, ORDER);
    if (!skipValidation) {
      if (!this.isValid(scalar))
        throw new Error("invalid field element: outside of range 0..ORDER");
    }
    return scalar;
  }
  // TODO: we don't need it here, move out to separate fn
  invertBatch(lst) {
    return FpInvertBatch(this, lst);
  }
  // We can't move this out because Fp6, Fp12 implement it
  // and it's unclear what to return in there.
  cmov(a, b, condition) {
    abool(condition, "condition");
    return condition ? b : a;
  }
};
Object.freeze(_Field.prototype);
function Field(ORDER, opts = {}) {
  return new _Field(ORDER, opts);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  if (fieldOrder <= _1n2)
    throw new Error("field order must be greater than 1");
  const bitLength = bitLen(fieldOrder - _1n2);
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key2, fieldOrder, isLE2 = false) {
  abytes2(key2);
  const len = key2.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = Math.max(getMinHashLength(fieldOrder), 16);
  if (len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num = isLE2 ? bytesToNumberLE(key2) : bytesToNumberBE(key2);
  const reduced = mod(num, fieldOrder - _1n2) + _1n2;
  return isLE2 ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}

// node_modules/@noble/curves/abstract/curve.js
var _0n3 = /* @__PURE__ */ BigInt(0);
var _1n3 = /* @__PURE__ */ BigInt(1);
function negateCt(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function normalizeZ(c, points) {
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n3;
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
var pointPrecomputes = /* @__PURE__ */ new WeakMap();
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getW(P2) {
  return pointWindowSizes.get(P2) || 1;
}
function assert0(n) {
  if (n !== _0n3)
    throw new Error("invalid wNAF");
}
var wNAF = class {
  BASE;
  ZERO;
  Fn;
  bits;
  // Parametrized with a given Point class (not individual point)
  constructor(Point, bits) {
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.Fn = Point.Fn;
    this.bits = bits;
  }
  // non-const time multiplication ladder
  _unsafeLadder(elm, n, p = this.ZERO) {
    let d = elm;
    while (n > _0n3) {
      if (n & _1n3)
        p = p.add(d);
      d = d.double();
      n >>= _1n3;
    }
    return p;
  }
  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Number of precomputed points depends on the curve size:
   * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
   * - 𝑊 is the window size
   * - 𝑛 is the bitlength of the curve order.
   * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
   * @param point - Point instance
   * @param W - window size
   * @returns precomputed point tables flattened to a single array
   */
  precomputeWindow(point, W) {
    const { windows, windowSize } = calcWOpts(W, this.bits);
    const points = [];
    let p = point;
    let base = p;
    for (let window = 0; window < windows; window++) {
      base = p;
      points.push(base);
      for (let i = 1; i < windowSize; i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }
  /**
   * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
   * More compact implementation:
   * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
   * @returns real and fake (for const-time) points
   */
  wNAF(W, precomputes, n) {
    if (!this.Fn.isValid(n))
      throw new Error("invalid scalar");
    let p = this.ZERO;
    let f = this.BASE;
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        f = f.add(negateCt(isNegF, precomputes[offsetF]));
      } else {
        p = p.add(negateCt(isNeg, precomputes[offset]));
      }
    }
    assert0(n);
    return { p, f };
  }
  /**
   * Implements unsafe EC multiplication using precomputed tables
   * and w-ary non-adjacent form.
   * @param acc - accumulator point to add result of multiplication
   * @returns point
   */
  wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
    const wo = calcWOpts(W, this.bits);
    for (let window = 0; window < wo.windows; window++) {
      if (n === _0n3)
        break;
      const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
      n = nextN;
      if (isZero) {
        continue;
      } else {
        const item = precomputes[offset];
        acc = acc.add(isNeg ? item.negate() : item);
      }
    }
    assert0(n);
    return acc;
  }
  getPrecomputes(W, point, transform) {
    let comp = pointPrecomputes.get(point);
    if (!comp) {
      comp = this.precomputeWindow(point, W);
      if (W !== 1) {
        if (typeof transform === "function")
          comp = transform(comp);
        pointPrecomputes.set(point, comp);
      }
    }
    return comp;
  }
  cached(point, scalar, transform) {
    const W = getW(point);
    return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
  }
  unsafe(point, scalar, transform, prev) {
    const W = getW(point);
    if (W === 1)
      return this._unsafeLadder(point, scalar, prev);
    return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
  }
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  createCache(P2, W) {
    validateW(W, this.bits);
    pointWindowSizes.set(P2, W);
    pointPrecomputes.delete(P2);
  }
  hasCache(elm) {
    return getW(elm) !== 1;
  }
};
function mulEndoUnsafe(Point, point, k1, k2) {
  let acc = point;
  let p1 = Point.ZERO;
  let p2 = Point.ZERO;
  while (k1 > _0n3 || k2 > _0n3) {
    if (k1 & _1n3)
      p1 = p1.add(acc);
    if (k2 & _1n3)
      p2 = p2.add(acc);
    acc = acc.double();
    k1 >>= _1n3;
    k2 >>= _1n3;
  }
  return { p1, p2 };
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(typeof val === "bigint" && val > _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b];
  for (const p of params) {
    if (!Fp.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp, Fn };
}
function createKeygen(randomSecretKey, getPublicKey) {
  return function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  };
}

// node_modules/@noble/curves/node_modules/@noble/hashes/hmac.js
var _HMAC = class {
  oHash;
  iHash;
  blockLen;
  outputLen;
  canXOF = false;
  finished = false;
  destroyed = false;
  constructor(hash, key2) {
    ahash(hash);
    abytes(key2, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key2.length > blockLen ? hash.create().update(key2).digest() : key2);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf2) {
    aexists(this);
    this.iHash.update(buf2);
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf2 = out.subarray(0, this.outputLen);
    this.iHash.digestInto(buf2);
    this.oHash.update(buf2);
    this.oHash.digestInto(buf2);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac2 = /* @__PURE__ */ (() => {
  const hmac_ = ((hash, key2, message) => new _HMAC(hash, key2).update(message).digest());
  hmac_.create = (hash, key2) => new _HMAC(hash, key2);
  return hmac_;
})();

// node_modules/@noble/curves/abstract/weierstrass.js
var divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n2) / den;
function _splitEndoScalar(k, basis, n) {
  aInRange("scalar", k, _0n4, n);
  const [[a1, b1], [a2, b2]] = basis;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n4;
  const k2neg = k2 < _0n4;
  if (k1neg)
    k1 = -k1;
  if (k2neg)
    k2 = -k2;
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n4;
  if (k1 < _0n4 || k1 >= MAX_NUM || k2 < _0n4 || k2 >= MAX_NUM) {
    throw new Error("splitScalar (endomorphism): failed for k");
  }
  return { k1neg, k1, k2neg, k2 };
}
function validateSigFormat(format) {
  if (!["compact", "recovered", "der"].includes(format))
    throw new Error('Signature format must be "compact", "recovered", or "der"');
  return format;
}
function validateSigOpts(opts, def) {
  validateObject(opts);
  const optsn = {};
  for (let optName of Object.keys(def)) {
    optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
  }
  abool(optsn.lowS, "lowS");
  abool(optsn.prehash, "prehash");
  if (optsn.format !== void 0)
    validateSigFormat(optsn.format);
  return optsn;
}
var DERErr = class extends Error {
  constructor(m = "") {
    super(m);
  }
};
var DER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = DER;
      asafenumber(tag, "tag");
      if (tag < 0 || tag > 255)
        throw new E("tlv.encode: wrong tag");
      if (typeof data !== "string")
        throw new TypeError('"data" expected string, got type=' + typeof data);
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag, data) {
      const { Err: E } = DER;
      data = abytes2(data, void 0, "DER data");
      let pos = 0;
      if (tag < 0 || tag > 255)
        throw new E("tlv.encode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num) {
      const { Err: E } = DER;
      abignumber(num);
      if (num < _0n4)
        throw new E("integer: negative integers are not allowed");
      let hex2 = numberToHexUnpadded(num);
      if (Number.parseInt(hex2[0], 16) & 8)
        hex2 = "00" + hex2;
      if (hex2.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex2;
    },
    decode(data) {
      const { Err: E } = DER;
      if (data.length < 1)
        throw new E("invalid signature integer: empty");
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data.length > 1 && data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return bytesToNumberBE(data);
    }
  },
  toSig(bytes) {
    const { Err: E, _int: int, _tlv: tlv } = DER;
    const data = abytes2(bytes, void 0, "signature");
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = DER;
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
Object.freeze(DER._tlv);
Object.freeze(DER._int);
Object.freeze(DER);
var _0n4 = /* @__PURE__ */ BigInt(0);
var _1n4 = /* @__PURE__ */ BigInt(1);
var _2n2 = /* @__PURE__ */ BigInt(2);
var _3n2 = /* @__PURE__ */ BigInt(3);
var _4n2 = /* @__PURE__ */ BigInt(4);
function weierstrass(params, extraOpts = {}) {
  const validated = createCurveFields("weierstrass", params, extraOpts);
  const Fp = validated.Fp;
  const Fn = validated.Fn;
  let CURVE = validated.CURVE;
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  validateObject(extraOpts, {}, {
    allowInfinityPoint: "boolean",
    clearCofactor: "function",
    isTorsionFree: "function",
    fromBytes: "function",
    toBytes: "function",
    endo: "object"
  });
  const { endo, allowInfinityPoint } = extraOpts;
  if (endo) {
    if (!Fp.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }
  const lengths = getWLengths(Fp, Fn);
  function assertCompressionIsSupported() {
    if (!Fp.isOdd)
      throw new Error("compression is not supported: Field does not have .isOdd()");
  }
  function pointToBytes(_c, point, isCompressed) {
    if (allowInfinityPoint && point.is0())
      return Uint8Array.of(0);
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    abool(isCompressed, "isCompressed");
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd(y);
      return concatBytes2(pprefix(hasEvenY), bx);
    } else {
      return concatBytes2(Uint8Array.of(4), bx, Fp.toBytes(y));
    }
  }
  function pointFromBytes(bytes) {
    abytes2(bytes, void 0, "Point");
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    if (allowInfinityPoint && length === 1 && head === 0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (length === comp && (head === 2 || head === 3)) {
      const x = Fp.fromBytes(tail);
      if (!Fp.isValid(x))
        throw new Error("bad point: is not on curve, wrong x");
      const y2 = weierstrassEquation(x);
      let y;
      try {
        y = Fp.sqrt(y2);
      } catch (sqrtError) {
        const err2 = sqrtError instanceof Error ? ": " + sqrtError.message : "";
        throw new Error("bad point: is not on curve, sqrt error" + err2);
      }
      assertCompressionIsSupported();
      const evenY = Fp.isOdd(y);
      const evenH = (head & 1) === 1;
      if (evenH !== evenY)
        y = Fp.neg(y);
      return { x, y };
    } else if (length === uncomp && head === 4) {
      const L = Fp.BYTES;
      const x = Fp.fromBytes(tail.subarray(0, L));
      const y = Fp.fromBytes(tail.subarray(L, L * 2));
      if (!isValidXY(x, y))
        throw new Error("bad point: is not on curve");
      return { x, y };
    } else {
      throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
    }
  }
  const encodePoint = extraOpts.toBytes === void 0 ? pointToBytes : extraOpts.toBytes;
  const decodePoint = extraOpts.fromBytes === void 0 ? pointFromBytes : extraOpts.fromBytes;
  function weierstrassEquation(x) {
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
  }
  function isValidXY(x, y) {
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    return Fp.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n2), _4n2);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function acoord(title, n, banZero = false) {
    if (!Fp.isValid(n) || banZero && Fp.is0(n))
      throw new Error(`bad point coordinate ${title}`);
    return n;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point))
      throw new Error("Weierstrass Point expected");
  }
  function splitEndoScalarN(k) {
    if (!endo || !endo.basises)
      throw new Error("no endo");
    return _splitEndoScalar(k, endo.basises, Fn.ORDER);
  }
  function finishEndo(endoBeta, k1p, k2p, k1neg, k2neg) {
    k2p = new Point(Fp.mul(k2p.X, endoBeta), k2p.Y, k2p.Z);
    k1p = negateCt(k1neg, k1p);
    k2p = negateCt(k2neg, k2p);
    return k1p.add(k2p);
  }
  class Point {
    // base / generator point
    static BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    // zero / infinity / identity point
    static ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
    // 0, 1, 0
    // math field
    static Fp = Fp;
    // scalar field
    static Fn = Fn;
    X;
    Y;
    Z;
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X, Y, Z) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y, true);
      this.Z = acoord("z", Z);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      if (Fp.is0(x) && Fp.is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }
    static fromBytes(bytes) {
      const P2 = Point.fromAffine(decodePoint(abytes2(bytes, void 0, "point")));
      P2.assertValidity();
      return P2;
    }
    static fromHex(hex2) {
      return Point.fromBytes(hexToBytes2(hex2));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     *
     * @param windowSize
     * @param isLazy - true will defer table computation until the first multiplication
     * @returns
     */
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_3n2);
      return this;
    }
    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity() {
      const p = this;
      if (p.is0()) {
        if (extraOpts.allowInfinityPoint && Fp.is0(p.X) && Fp.eql(p.Y, Fp.ONE) && Fp.is0(p.Z))
          return;
        throw new Error("bad point: ZERO");
      }
      const { x, y } = p.toAffine();
      if (!Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("bad point: x or y not field elements");
      if (!isValidXY(x, y))
        throw new Error("bad point: equation left != right");
      if (!p.isTorsionFree())
        throw new Error("bad point: not in prime-order subgroup");
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (!Fp.isOdd)
        throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }
    /** Compare one point to another. */
    equals(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate() {
      return new Point(this.X, Fp.neg(this.Y), this.Z);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n2);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n2);
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      aprjpoint(other);
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar - by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar) {
      const { endo: endo2 } = extraOpts;
      if (!Fn.isValidNot0(scalar))
        throw new RangeError("invalid scalar: out of range");
      let point, fake;
      const mul2 = (n) => wnaf.cached(this, n, (p) => normalizeZ(Point, p));
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(scalar);
        const { p: k1p, f: k1f } = mul2(k1);
        const { p: k2p, f: k2f } = mul2(k2);
        fake = k1f.add(k2f);
        point = finishEndo(endo2.beta, k1p, k2p, k1neg, k2neg);
      } else {
        const { p, f } = mul2(scalar);
        point = p;
        fake = f;
      }
      return normalizeZ(Point, [point, fake])[0];
    }
    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(scalar) {
      const { endo: endo2 } = extraOpts;
      const p = this;
      const sc = scalar;
      if (!Fn.isValid(sc))
        throw new RangeError("invalid scalar: out of range");
      if (sc === _0n4 || p.is0())
        return Point.ZERO;
      if (sc === _1n4)
        return p;
      if (wnaf.hasCache(this))
        return this.multiply(sc);
      if (endo2) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(sc);
        const { p1, p2 } = mulEndoUnsafe(Point, p, k1, k2);
        return finishEndo(endo2.beta, p1, p2, k1neg, k2neg);
      } else {
        return wnaf.unsafe(p, sc);
      }
    }
    /**
     * Converts Projective point to affine (x, y) coordinates.
     * (X, Y, Z) ∋ (x=X/Z, y=Y/Z).
     * @param invertedZ - Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ) {
      const p = this;
      let iz = invertedZ;
      const { X, Y, Z } = p;
      if (Fp.eql(Z, Fp.ONE))
        return { x: X, y: Y };
      const is0 = p.is0();
      if (iz == null)
        iz = is0 ? Fp.ONE : Fp.inv(Z);
      const x = Fp.mul(X, iz);
      const y = Fp.mul(Y, iz);
      const zz = Fp.mul(Z, iz);
      if (is0)
        return { x: Fp.ZERO, y: Fp.ZERO };
      if (!Fp.eql(zz, Fp.ONE))
        throw new Error("invZ was invalid");
      return { x, y };
    }
    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree() {
      const { isTorsionFree } = extraOpts;
      if (cofactor === _1n4)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      return wnaf.unsafe(this, CURVE_ORDER).is0();
    }
    clearCofactor() {
      const { clearCofactor } = extraOpts;
      if (cofactor === _1n4)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(cofactor);
    }
    isSmallOrder() {
      if (cofactor === _1n4)
        return this.is0();
      return this.clearCofactor().is0();
    }
    toBytes(isCompressed = true) {
      abool(isCompressed, "isCompressed");
      this.assertValidity();
      return encodePoint(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      return bytesToHex2(this.toBytes(isCompressed));
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
  }
  const bits = Fn.BITS;
  const wnaf = new wNAF(Point, extraOpts.endo ? Math.ceil(bits / 2) : bits);
  if (bits >= 8)
    Point.BASE.precompute(8);
  Object.freeze(Point.prototype);
  Object.freeze(Point);
  return Point;
}
function pprefix(hasEvenY) {
  return Uint8Array.of(hasEvenY ? 2 : 3);
}
function getWLengths(Fp, Fn) {
  return {
    secretKey: Fn.BYTES,
    publicKey: 1 + Fp.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp.BYTES,
    publicKeyHasPrefix: true,
    // Raw compact `(r || s)` signature width; DER and recovered signatures use
    // different lengths outside this helper.
    signature: 2 * Fn.BYTES
  };
}
function ecdh2(Point, ecdhOpts = {}) {
  const { Fn } = Point;
  const randomBytes_ = ecdhOpts.randomBytes === void 0 ? randomBytes3 : ecdhOpts.randomBytes;
  const lengths = Object.assign(getWLengths(Point.Fp, Fn), {
    seed: Math.max(getMinHashLength(Fn.ORDER), 16)
  });
  function isValidSecretKey(secretKey) {
    try {
      const num = Fn.fromBytes(secretKey);
      return Fn.isValidNot0(num);
    } catch (error) {
      return false;
    }
  }
  function isValidPublicKey(publicKey, isCompressed) {
    const { publicKey: comp, publicKeyUncompressed } = lengths;
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== comp)
        return false;
      if (isCompressed === false && l !== publicKeyUncompressed)
        return false;
      return !!Point.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  }
  function randomSecretKey(seed) {
    seed = seed === void 0 ? randomBytes_(lengths.seed) : seed;
    return mapHashToField(abytes2(seed, lengths.seed, "seed"), Fn.ORDER);
  }
  function getPublicKey(secretKey, isCompressed = true) {
    return Point.BASE.multiply(Fn.fromBytes(secretKey)).toBytes(isCompressed);
  }
  function isProbPub(item) {
    const { secretKey, publicKey, publicKeyUncompressed } = lengths;
    const allowedLengths = Fn._lengths;
    if (!isBytes2(item))
      return void 0;
    const l = abytes2(item, void 0, "key").length;
    const isPub = l === publicKey || l === publicKeyUncompressed;
    const isSec = l === secretKey || !!allowedLengths?.includes(l);
    if (isPub && isSec)
      return void 0;
    return isPub;
  }
  function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
    if (isProbPub(secretKeyA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicKeyB) === false)
      throw new Error("second arg must be public key");
    const s = Fn.fromBytes(secretKeyA);
    const b = Point.fromBytes(publicKeyB);
    return b.multiply(s).toBytes(isCompressed);
  }
  const utils = {
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey
  };
  const keygen = createKeygen(randomSecretKey, getPublicKey);
  Object.freeze(utils);
  Object.freeze(lengths);
  return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
}
function ecdsa(Point, hash, ecdsaOpts = {}) {
  const hash_ = hash;
  ahash(hash_);
  validateObject(ecdsaOpts, {}, {
    hmac: "function",
    lowS: "boolean",
    randomBytes: "function",
    bits2int: "function",
    bits2int_modN: "function"
  });
  ecdsaOpts = Object.assign({}, ecdsaOpts);
  const randomBytes5 = ecdsaOpts.randomBytes === void 0 ? randomBytes3 : ecdsaOpts.randomBytes;
  const hmac3 = ecdsaOpts.hmac === void 0 ? (key2, msg) => hmac2(hash_, key2, msg) : ecdsaOpts.hmac;
  const { Fp, Fn } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;
  const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh2(Point, ecdsaOpts);
  const defaultSigOpts = {
    prehash: true,
    lowS: typeof ecdsaOpts.lowS === "boolean" ? ecdsaOpts.lowS : true,
    format: "compact",
    extraEntropy: false
  };
  const hasLargeRecoveryLifts = CURVE_ORDER * _2n2 + _1n4 < Fp.ORDER;
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n4;
    return number > HALF;
  }
  function validateRS(title, num) {
    if (!Fn.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
    return num;
  }
  function assertRecoverableCurve() {
    if (hasLargeRecoveryLifts)
      throw new Error('"recovered" sig type is not supported for cofactor >2 curves');
  }
  function validateSigLength(bytes, format) {
    validateSigFormat(format);
    const size = lengths.signature;
    const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
    return abytes2(bytes, sizer);
  }
  class Signature {
    r;
    s;
    recovery;
    constructor(r, s, recovery) {
      this.r = validateRS("r", r);
      this.s = validateRS("s", s);
      if (recovery != null) {
        assertRecoverableCurve();
        if (![0, 1, 2, 3].includes(recovery))
          throw new Error("invalid recovery id");
        this.recovery = recovery;
      }
      Object.freeze(this);
    }
    static fromBytes(bytes, format = defaultSigOpts.format) {
      validateSigLength(bytes, format);
      let recid;
      if (format === "der") {
        const { r: r2, s: s2 } = DER.toSig(abytes2(bytes));
        return new Signature(r2, s2);
      }
      if (format === "recovered") {
        recid = bytes[0];
        format = "compact";
        bytes = bytes.subarray(1);
      }
      const L = lengths.signature / 2;
      const r = bytes.subarray(0, L);
      const s = bytes.subarray(L, L * 2);
      return new Signature(Fn.fromBytes(r), Fn.fromBytes(s), recid);
    }
    static fromHex(hex2, format) {
      return this.fromBytes(hexToBytes2(hex2), format);
    }
    assertRecovery() {
      const { recovery } = this;
      if (recovery == null)
        throw new Error("invalid recovery id: must be present");
      return recovery;
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    // Unlike the top-level helper below, this method expects a digest that has
    // already been hashed to the curve's message representative.
    recoverPublicKey(messageHash) {
      const { r, s } = this;
      const recovery = this.assertRecovery();
      const radj = recovery === 2 || recovery === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj))
        throw new Error("invalid recovery id: sig.r+curve.n != R.x");
      const x = Fp.toBytes(radj);
      const R = Point.fromBytes(concatBytes2(pprefix((recovery & 1) === 0), x));
      const ir = Fn.inv(radj);
      const h = bits2int_modN(abytes2(messageHash, void 0, "msgHash"));
      const u1 = Fn.create(-h * ir);
      const u2 = Fn.create(s * ir);
      const Q = Point.BASE.multiplyUnsafe(u1).add(R.multiplyUnsafe(u2));
      if (Q.is0())
        throw new Error("invalid recovery: point at infinify");
      Q.assertValidity();
      return Q;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    toBytes(format = defaultSigOpts.format) {
      validateSigFormat(format);
      if (format === "der")
        return hexToBytes2(DER.hexFromSig(this));
      const { r, s } = this;
      const rb = Fn.toBytes(r);
      const sb = Fn.toBytes(s);
      if (format === "recovered") {
        assertRecoverableCurve();
        return concatBytes2(Uint8Array.of(this.assertRecovery()), rb, sb);
      }
      return concatBytes2(rb, sb);
    }
    toHex(format) {
      return bytesToHex2(this.toBytes(format));
    }
  }
  Object.freeze(Signature.prototype);
  Object.freeze(Signature);
  const bits2int = ecdsaOpts.bits2int === void 0 ? function bits2int_def(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - fnBits;
    return delta > 0 ? num >> BigInt(delta) : num;
  } : ecdsaOpts.bits2int;
  const bits2int_modN = ecdsaOpts.bits2int_modN === void 0 ? function bits2int_modN_def(bytes) {
    return Fn.create(bits2int(bytes));
  } : ecdsaOpts.bits2int_modN;
  const ORDER_MASK = bitMask(fnBits);
  function int2octets(num) {
    aInRange("num < 2^" + fnBits, num, _0n4, ORDER_MASK);
    return Fn.toBytes(num);
  }
  function validateMsgAndHash(message, prehash) {
    abytes2(message, void 0, "message");
    return prehash ? abytes2(hash_(message), void 0, "prehashed message") : message;
  }
  function prepSig(message, secretKey, opts) {
    const { lowS, prehash, extraEntropy } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    const h1int = bits2int_modN(message);
    const d = Fn.fromBytes(secretKey);
    if (!Fn.isValidNot0(d))
      throw new Error("invalid private key");
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (extraEntropy != null && extraEntropy !== false) {
      const e = extraEntropy === true ? randomBytes5(lengths.secretKey) : extraEntropy;
      seedArgs.push(abytes2(e, void 0, "extraEntropy"));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!Fn.isValidNot0(k))
        return;
      const ik = Fn.inv(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = Fn.create(q.x);
      if (r === _0n4)
        return;
      const s = Fn.create(ik * Fn.create(m + r * d));
      if (s === _0n4)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n4);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = Fn.neg(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, hasLargeRecoveryLifts ? void 0 : recovery);
    }
    return { seed, k2sig };
  }
  function sign(message, secretKey, opts = {}) {
    const { seed, k2sig } = prepSig(message, secretKey, opts);
    const drbg = createHmacDrbg(hash_.outputLen, Fn.BYTES, hmac3);
    const sig = drbg(seed, k2sig);
    return sig.toBytes(opts.format);
  }
  function verify(signature, message, publicKey, opts = {}) {
    const { lowS, prehash, format } = validateSigOpts(opts, defaultSigOpts);
    publicKey = abytes2(publicKey, void 0, "publicKey");
    message = validateMsgAndHash(message, prehash);
    if (!isBytes2(signature)) {
      const end = signature instanceof Signature ? ", use sig.toBytes()" : "";
      throw new Error("verify expects Uint8Array signature" + end);
    }
    validateSigLength(signature, format);
    try {
      const sig = Signature.fromBytes(signature, format);
      const P2 = Point.fromBytes(publicKey);
      if (lowS && sig.hasHighS())
        return false;
      const { r, s } = sig;
      const h = bits2int_modN(message);
      const is = Fn.inv(s);
      const u1 = Fn.create(h * is);
      const u2 = Fn.create(r * is);
      const R = Point.BASE.multiplyUnsafe(u1).add(P2.multiplyUnsafe(u2));
      if (R.is0())
        return false;
      const v = Fn.create(R.x);
      return v === r;
    } catch (e) {
      return false;
    }
  }
  function recoverPublicKey(signature, message, opts = {}) {
    const { prehash } = validateSigOpts(opts, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
  }
  return Object.freeze({
    keygen,
    getPublicKey,
    getSharedSecret,
    utils,
    lengths,
    Point,
    sign,
    verify,
    recoverPublicKey,
    Signature,
    hash: hash_
  });
}

// node_modules/@noble/curves/nist.js
var p256_CURVE = /* @__PURE__ */ (() => ({
  p: BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
  n: BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
  h: BigInt(1),
  a: BigInt("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
  b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
  Gx: BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
  Gy: BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
}))();
var p256_Point = /* @__PURE__ */ weierstrass(p256_CURVE);
var p256 = /* @__PURE__ */ ecdsa(p256_Point, sha2562);

// node_modules/@noble/hashes/utils.js
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber3(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes3(value, length, title = "") {
  if (isBytes3(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber3(length, "length");
  const bytes = isBytes3(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function copyBytes2(bytes) {
  return Uint8Array.from(abytes3(bytes));
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists2(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput2(out, instance) {
  abytes3(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean2(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
var swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n) >>> 0;
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new TypeError("string expected");
  const encoded = new TextEncoder().encode(str);
  try {
    return new Uint8Array(encoded);
  } finally {
    clean2(encoded);
  }
}
function kdfInputToBytes(data, errorTitle = "") {
  if (typeof data === "string")
    return utf8ToBytes(data);
  return abytes3(data, void 0, errorTitle);
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher2(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}

// node_modules/@noble/hashes/_blake.js
var BSIGMA = /* @__PURE__ */ Uint8Array.from([
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  14,
  10,
  4,
  8,
  9,
  15,
  13,
  6,
  1,
  12,
  0,
  2,
  11,
  7,
  5,
  3,
  11,
  8,
  12,
  0,
  5,
  2,
  15,
  13,
  10,
  14,
  3,
  6,
  7,
  1,
  9,
  4,
  7,
  9,
  3,
  1,
  13,
  12,
  11,
  14,
  2,
  6,
  5,
  10,
  4,
  0,
  15,
  8,
  9,
  0,
  5,
  7,
  2,
  4,
  10,
  15,
  14,
  1,
  11,
  12,
  6,
  8,
  3,
  13,
  2,
  12,
  6,
  10,
  0,
  11,
  8,
  3,
  4,
  13,
  7,
  5,
  15,
  14,
  1,
  9,
  12,
  5,
  1,
  15,
  14,
  13,
  4,
  10,
  0,
  7,
  6,
  3,
  9,
  2,
  8,
  11,
  13,
  11,
  7,
  14,
  12,
  1,
  3,
  9,
  5,
  0,
  15,
  4,
  8,
  6,
  2,
  10,
  6,
  15,
  14,
  9,
  11,
  3,
  0,
  8,
  12,
  2,
  13,
  7,
  1,
  4,
  10,
  5,
  10,
  2,
  8,
  4,
  7,
  6,
  1,
  5,
  15,
  11,
  9,
  14,
  3,
  12,
  13,
  0,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  14,
  10,
  4,
  8,
  9,
  15,
  13,
  6,
  1,
  12,
  0,
  2,
  11,
  7,
  5,
  3,
  // Blake1, unused in others
  11,
  8,
  12,
  0,
  5,
  2,
  15,
  13,
  10,
  14,
  3,
  6,
  7,
  1,
  9,
  4,
  7,
  9,
  3,
  1,
  13,
  12,
  11,
  14,
  2,
  6,
  5,
  10,
  4,
  0,
  15,
  8,
  9,
  0,
  5,
  7,
  2,
  4,
  10,
  15,
  14,
  1,
  11,
  12,
  6,
  8,
  3,
  13,
  2,
  12,
  6,
  10,
  0,
  11,
  8,
  3,
  4,
  13,
  7,
  5,
  15,
  14,
  1,
  9
]);

// node_modules/@noble/hashes/_u64.js
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
var rotr32H = (_h, l) => l;
var rotr32L = (h, _l) => h;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;

// node_modules/@noble/hashes/blake2.js
var B2B_IV = /* @__PURE__ */ Uint32Array.from([
  4089235720,
  1779033703,
  2227873595,
  3144134277,
  4271175723,
  1013904242,
  1595750129,
  2773480762,
  2917565137,
  1359893119,
  725511199,
  2600822924,
  4215389547,
  528734635,
  327033209,
  1541459225
]);
var BBUF = /* @__PURE__ */ new Uint32Array(32);
function G1b(a, b, c, d, msg, x) {
  const Xl = msg[x], Xh = msg[x + 1];
  let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1];
  let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1];
  let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1];
  let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1];
  const ll = add3L(Al, Bl, Xl);
  Ah = add3H(ll, Ah, Bh, Xh);
  Al = ll | 0;
  let xh = Dh ^ Ah, xl = Dl ^ Al;
  Dh = rotr32H(xh, xl);
  Dl = rotr32L(xh, xl);
  ({ h: Ch, l: Cl } = add(Ch, Cl, Dh, Dl));
  xh = Bh ^ Ch;
  xl = Bl ^ Cl;
  Bh = rotrSH(xh, xl, 24);
  Bl = rotrSL(xh, xl, 24);
  BBUF[2 * a] = Al;
  BBUF[2 * a + 1] = Ah;
  BBUF[2 * b] = Bl;
  BBUF[2 * b + 1] = Bh;
  BBUF[2 * c] = Cl;
  BBUF[2 * c + 1] = Ch;
  BBUF[2 * d] = Dl;
  BBUF[2 * d + 1] = Dh;
}
function G2b(a, b, c, d, msg, x) {
  const Xl = msg[x], Xh = msg[x + 1];
  let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1];
  let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1];
  let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1];
  let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1];
  const ll = add3L(Al, Bl, Xl);
  Ah = add3H(ll, Ah, Bh, Xh);
  Al = ll | 0;
  let xh = Dh ^ Ah, xl = Dl ^ Al;
  Dh = rotrSH(xh, xl, 16);
  Dl = rotrSL(xh, xl, 16);
  ({ h: Ch, l: Cl } = add(Ch, Cl, Dh, Dl));
  xh = Bh ^ Ch;
  xl = Bl ^ Cl;
  Bh = rotrBH(xh, xl, 63);
  Bl = rotrBL(xh, xl, 63);
  BBUF[2 * a] = Al;
  BBUF[2 * a + 1] = Ah;
  BBUF[2 * b] = Bl;
  BBUF[2 * b + 1] = Bh;
  BBUF[2 * c] = Cl;
  BBUF[2 * c + 1] = Ch;
  BBUF[2 * d] = Dl;
  BBUF[2 * d + 1] = Dh;
}
function checkBlake2Opts(outputLen, opts = {}, keyLen, saltLen, persLen) {
  anumber3(keyLen);
  if (outputLen <= 0 || outputLen > keyLen)
    throw new Error('"dkLen" must be 1..' + keyLen + ", got " + outputLen);
  const { key: key2, salt, personalization } = opts;
  if (key2 !== void 0 && (key2.length < 1 || key2.length > keyLen))
    throw new Error('"key" expected to be undefined or of length=1..' + keyLen);
  if (salt !== void 0)
    abytes3(salt, saltLen, "salt");
  if (personalization !== void 0)
    abytes3(personalization, persLen, "personalization");
}
var _BLAKE2 = class {
  buffer;
  buffer32;
  finished = false;
  destroyed = false;
  length = 0;
  pos = 0;
  blockLen;
  outputLen;
  canXOF = false;
  constructor(blockLen, outputLen) {
    anumber3(blockLen);
    anumber3(outputLen);
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.buffer = new Uint8Array(blockLen);
    this.buffer32 = u32(this.buffer);
  }
  update(data) {
    aexists2(this);
    abytes3(data);
    const { blockLen, buffer, buffer32 } = this;
    const len = data.length;
    const offset = data.byteOffset;
    const buf2 = data.buffer;
    for (let pos = 0; pos < len; ) {
      if (this.pos === blockLen) {
        swap32IfBE(buffer32);
        this.compress(buffer32, 0, false);
        swap32IfBE(buffer32);
        this.pos = 0;
      }
      const take = Math.min(blockLen - this.pos, len - pos);
      const dataOffset = offset + pos;
      if (take === blockLen && !(dataOffset % 4) && pos + take < len) {
        const data32 = new Uint32Array(buf2, dataOffset, Math.floor((len - pos) / 4));
        swap32IfBE(data32);
        for (let pos32 = 0; pos + blockLen < len; pos32 += buffer32.length, pos += blockLen) {
          this.length += blockLen;
          this.compress(data32, pos32, false);
        }
        swap32IfBE(data32);
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      this.length += take;
      pos += take;
    }
    return this;
  }
  digestInto(out) {
    aexists2(this);
    aoutput2(out, this);
    if (out.byteOffset & 3)
      throw new RangeError('"output" expected 4-byte aligned byteOffset, got ' + out.byteOffset);
    const { pos, buffer32 } = this;
    this.finished = true;
    this.buffer.fill(0, pos);
    swap32IfBE(buffer32);
    this.compress(buffer32, 0, true);
    swap32IfBE(buffer32);
    const state = this.get();
    const out32 = out === this.buffer ? buffer32 : u32(out);
    const full = Math.floor(this.outputLen / 4);
    for (let i = 0; i < full; i++)
      out32[i] = swap8IfBE(state[i]);
    const tail = this.outputLen % 4;
    if (!tail)
      return;
    const off = full * 4;
    const word = state[full];
    for (let i = 0; i < tail; i++)
      out[off + i] = word >>> 8 * i;
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    const { buffer, length, finished, destroyed, outputLen, pos } = this;
    to ||= new this.constructor({ dkLen: outputLen });
    to.set(...this.get());
    to.buffer.set(buffer);
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    to.outputLen = outputLen;
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var _BLAKE2b = class extends _BLAKE2 {
  // Same IV words as SHA-512 / BLAKE2b, encoded as LE u32 low/high halves.
  v0l = B2B_IV[0] | 0;
  v0h = B2B_IV[1] | 0;
  v1l = B2B_IV[2] | 0;
  v1h = B2B_IV[3] | 0;
  v2l = B2B_IV[4] | 0;
  v2h = B2B_IV[5] | 0;
  v3l = B2B_IV[6] | 0;
  v3h = B2B_IV[7] | 0;
  v4l = B2B_IV[8] | 0;
  v4h = B2B_IV[9] | 0;
  v5l = B2B_IV[10] | 0;
  v5h = B2B_IV[11] | 0;
  v6l = B2B_IV[12] | 0;
  v6h = B2B_IV[13] | 0;
  v7l = B2B_IV[14] | 0;
  v7h = B2B_IV[15] | 0;
  constructor(opts = {}) {
    opts = checkOpts({}, opts);
    const olen = opts.dkLen === void 0 ? 64 : opts.dkLen;
    super(128, olen);
    checkBlake2Opts(olen, opts, 64, 16, 16);
    let { key: key2, personalization, salt } = opts;
    let keyLength = 0;
    if (key2 !== void 0) {
      abytes3(key2, void 0, "key");
      keyLength = key2.length;
    }
    this.v0l ^= this.outputLen | keyLength << 8 | 1 << 16 | 1 << 24;
    if (salt !== void 0) {
      abytes3(salt, void 0, "salt");
      const slt = u32(copyBytes2(salt));
      this.v4l ^= swap8IfBE(slt[0]);
      this.v4h ^= swap8IfBE(slt[1]);
      this.v5l ^= swap8IfBE(slt[2]);
      this.v5h ^= swap8IfBE(slt[3]);
    }
    if (personalization !== void 0) {
      abytes3(personalization, void 0, "personalization");
      const pers = u32(copyBytes2(personalization));
      this.v6l ^= swap8IfBE(pers[0]);
      this.v6h ^= swap8IfBE(pers[1]);
      this.v7l ^= swap8IfBE(pers[2]);
      this.v7h ^= swap8IfBE(pers[3]);
    }
    if (key2 !== void 0) {
      const tmp = new Uint8Array(this.blockLen);
      tmp.set(key2);
      this.update(tmp);
      clean2(tmp);
    }
  }
  // prettier-ignore
  get() {
    let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
    return [v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h];
  }
  // prettier-ignore
  set(v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h) {
    this.v0l = v0l | 0;
    this.v0h = v0h | 0;
    this.v1l = v1l | 0;
    this.v1h = v1h | 0;
    this.v2l = v2l | 0;
    this.v2h = v2h | 0;
    this.v3l = v3l | 0;
    this.v3h = v3h | 0;
    this.v4l = v4l | 0;
    this.v4h = v4h | 0;
    this.v5l = v5l | 0;
    this.v5h = v5h | 0;
    this.v6l = v6l | 0;
    this.v6h = v6h | 0;
    this.v7l = v7l | 0;
    this.v7h = v7h | 0;
  }
  compress(msg, offset, isLast) {
    const { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
    {
      BBUF[0] = v0l;
      BBUF[1] = v0h;
      BBUF[2] = v1l;
      BBUF[3] = v1h;
      BBUF[4] = v2l;
      BBUF[5] = v2h;
      BBUF[6] = v3l;
      BBUF[7] = v3h;
      BBUF[8] = v4l;
      BBUF[9] = v4h;
      BBUF[10] = v5l;
      BBUF[11] = v5h;
      BBUF[12] = v6l;
      BBUF[13] = v6h;
      BBUF[14] = v7l;
      BBUF[15] = v7h;
    }
    BBUF.set(B2B_IV, 16);
    const l = fromNumL(this.length);
    const h = fromNumH(this.length);
    BBUF[24] = B2B_IV[8] ^ l;
    BBUF[25] = B2B_IV[9] ^ h;
    if (isLast) {
      BBUF[28] = ~BBUF[28];
      BBUF[29] = ~BBUF[29];
    }
    let j = 0;
    const s = BSIGMA;
    for (let i = 0; i < 12; i++) {
      G1b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
      G2b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
      G1b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
      G2b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
      G1b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
      G2b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
      G1b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
      G2b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
      G1b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
      G2b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
      G1b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
      G2b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
      G1b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
      G2b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
      G1b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
      G2b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
    }
    this.v0l ^= BBUF[0] ^ BBUF[16];
    this.v0h ^= BBUF[1] ^ BBUF[17];
    this.v1l ^= BBUF[2] ^ BBUF[18];
    this.v1h ^= BBUF[3] ^ BBUF[19];
    this.v2l ^= BBUF[4] ^ BBUF[20];
    this.v2h ^= BBUF[5] ^ BBUF[21];
    this.v3l ^= BBUF[6] ^ BBUF[22];
    this.v3h ^= BBUF[7] ^ BBUF[23];
    this.v4l ^= BBUF[8] ^ BBUF[24];
    this.v4h ^= BBUF[9] ^ BBUF[25];
    this.v5l ^= BBUF[10] ^ BBUF[26];
    this.v5h ^= BBUF[11] ^ BBUF[27];
    this.v6l ^= BBUF[12] ^ BBUF[28];
    this.v6h ^= BBUF[13] ^ BBUF[29];
    this.v7l ^= BBUF[14] ^ BBUF[30];
    this.v7h ^= BBUF[15] ^ BBUF[31];
    clean2(BBUF);
  }
  destroy() {
    this.destroyed = true;
    clean2(this.buffer32);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var blake2b = /* @__PURE__ */ createHasher2((opts) => new _BLAKE2b(opts));

// node_modules/@noble/hashes/argon2.js
var AT = { Argon2d: 0, Argon2i: 1, Argon2id: 2 };
var ARGON2_SYNC_POINTS = 4;
var abytesOrZero = (buf2, errorTitle = "") => {
  if (buf2 === void 0)
    return Uint8Array.of();
  return kdfInputToBytes(buf2, errorTitle);
};
var A2_BUF = new Uint32Array(256);
function G(a, b, c, d) {
  let Al = A2_BUF[2 * a], Ah = A2_BUF[2 * a + 1];
  let Bl = A2_BUF[2 * b], Bh = A2_BUF[2 * b + 1];
  let Cl = A2_BUF[2 * c], Ch = A2_BUF[2 * c + 1];
  let Dl = A2_BUF[2 * d], Dh = A2_BUF[2 * d + 1];
  let ml = 0, mh = 0, rl = 0, xh = 0, xl = 0;
  ml = Math.imul(Al, Bl);
  mh = ((Al >>> 0) * (Bl >>> 0) - (ml >>> 0)) / 4294967296 + 0.5 | 0;
  rl = (Al >>> 0) + (Bl >>> 0) + (ml << 1 >>> 0);
  Ah = Ah + Bh + (mh << 1 | ml >>> 31) + (rl / 4294967296 | 0) | 0;
  Al = rl | 0;
  xh = Dh ^ Ah;
  xl = Dl ^ Al;
  Dh = xl;
  Dl = xh;
  ml = Math.imul(Cl, Dl);
  mh = ((Cl >>> 0) * (Dl >>> 0) - (ml >>> 0)) / 4294967296 + 0.5 | 0;
  rl = (Cl >>> 0) + (Dl >>> 0) + (ml << 1 >>> 0);
  Ch = Ch + Dh + (mh << 1 | ml >>> 31) + (rl / 4294967296 | 0) | 0;
  Cl = rl | 0;
  xh = Bh ^ Ch;
  xl = Bl ^ Cl;
  Bh = xh >>> 24 | xl << 8;
  Bl = xh << 8 | xl >>> 24;
  ml = Math.imul(Al, Bl);
  mh = ((Al >>> 0) * (Bl >>> 0) - (ml >>> 0)) / 4294967296 + 0.5 | 0;
  rl = (Al >>> 0) + (Bl >>> 0) + (ml << 1 >>> 0);
  Ah = Ah + Bh + (mh << 1 | ml >>> 31) + (rl / 4294967296 | 0) | 0;
  Al = rl | 0;
  xh = Dh ^ Ah;
  xl = Dl ^ Al;
  Dh = xh >>> 16 | xl << 16;
  Dl = xh << 16 | xl >>> 16;
  ml = Math.imul(Cl, Dl);
  mh = ((Cl >>> 0) * (Dl >>> 0) - (ml >>> 0)) / 4294967296 + 0.5 | 0;
  rl = (Cl >>> 0) + (Dl >>> 0) + (ml << 1 >>> 0);
  Ch = Ch + Dh + (mh << 1 | ml >>> 31) + (rl / 4294967296 | 0) | 0;
  Cl = rl | 0;
  xh = Bh ^ Ch;
  xl = Bl ^ Cl;
  Bh = xh << 1 | xl >>> 31;
  Bl = xh >>> 31 | xl << 1;
  A2_BUF[2 * a] = Al, A2_BUF[2 * a + 1] = Ah;
  A2_BUF[2 * b] = Bl, A2_BUF[2 * b + 1] = Bh;
  A2_BUF[2 * c] = Cl, A2_BUF[2 * c + 1] = Ch;
  A2_BUF[2 * d] = Dl, A2_BUF[2 * d + 1] = Dh;
}
function P(v00, v01, v02, v03, v04, v05, v06, v07, v08, v09, v10, v11, v12, v13, v14, v15) {
  G(v00, v04, v08, v12);
  G(v01, v05, v09, v13);
  G(v02, v06, v10, v14);
  G(v03, v07, v11, v15);
  G(v00, v05, v10, v15);
  G(v01, v06, v11, v12);
  G(v02, v07, v08, v13);
  G(v03, v04, v09, v14);
}
function block(x, xPos, yPos, outPos, needXor) {
  if (needXor) {
    for (let i = 0; i < 256; i++) {
      const r = x[xPos + i] ^ x[yPos + i];
      A2_BUF[i] = r;
      x[outPos + i] ^= r;
    }
  } else {
    for (let i = 0; i < 256; i++) {
      const r = x[xPos + i] ^ x[yPos + i];
      A2_BUF[i] = r;
      x[outPos + i] = r;
    }
  }
  for (let i = 0; i < 128; i += 16) {
    P(i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15);
  }
  for (let i = 0; i < 16; i += 2) {
    P(i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49, i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
  }
  for (let i = 0; i < 256; i++)
    x[outPos + i] ^= A2_BUF[i];
  clean2(A2_BUF);
}
function Hp(A, dkLen) {
  const A8 = u8(A);
  const T = new Uint32Array(1);
  const T8 = u8(T);
  T[0] = swap8IfBE(dkLen);
  if (dkLen <= 64)
    return blake2b.create({ dkLen }).update(T8).update(A8).digest();
  const out = new Uint8Array(dkLen);
  let V = blake2b.create({}).update(T8).update(A8).digest();
  let pos = 0;
  out.set(V.subarray(0, 32));
  pos += 32;
  for (; dkLen - pos > 64; pos += 32) {
    const Vh = blake2b.create({}).update(V);
    Vh.digestInto(V);
    Vh.destroy();
    out.set(V.subarray(0, 32), pos);
  }
  out.set(blake2b(V, { dkLen: dkLen - pos }), pos);
  clean2(V, T);
  return out;
}
function indexAlpha(r, s, laneLen, segmentLen, index, randL, sameLane = false) {
  let area;
  if (r === 0) {
    if (s === 0)
      area = index - 1;
    else if (sameLane)
      area = s * segmentLen + index - 1;
    else
      area = s * segmentLen + (index == 0 ? -1 : 0);
  } else if (sameLane)
    area = laneLen - segmentLen + index - 1;
  else
    area = laneLen - segmentLen + (index == 0 ? -1 : 0);
  const startPos = r !== 0 && s !== ARGON2_SYNC_POINTS - 1 ? (s + 1) * segmentLen : 0;
  const randLow = Math.imul(randL, randL);
  const randHigh = ((randL >>> 0) * (randL >>> 0) - (randLow >>> 0)) / 4294967296 + 0.5 | 0;
  const areaLow = Math.imul(area, randHigh);
  const areaHigh = ((area >>> 0) * (randHigh >>> 0) - (areaLow >>> 0)) / 4294967296 + 0.5 | 0;
  const rel = area - 1 - areaHigh;
  return (startPos + rel) % laneLen;
}
var maxUint32 = Math.pow(2, 32);
var ARGON2_DEFAULT_MEMORY = 1024 ** 2;
var ARGON2_DEFAULT_MAXMEM = ARGON2_DEFAULT_MEMORY * 1024;
function isU32(num) {
  return Number.isSafeInteger(num) && num >= 0 && num < maxUint32;
}
function argon2Opts(opts = {}) {
  opts = checkOpts({}, opts);
  const merged = {
    t: 3,
    m: ARGON2_DEFAULT_MEMORY,
    p: 1,
    version: 19,
    dkLen: 32,
    maxmem: ARGON2_DEFAULT_MAXMEM,
    asyncTick: 10
  };
  for (let [k, v] of Object.entries(opts))
    if (v !== void 0)
      merged[k] = v;
  const { dkLen, p, m, t, version, onProgress, asyncTick } = merged;
  if (!isU32(dkLen) || dkLen < 4)
    throw new Error('"dkLen" must be 4..');
  if (!isU32(p) || p < 1 || p >= Math.pow(2, 24))
    throw new Error('"p" must be 1..2^24');
  if (!isU32(m))
    throw new Error('"m" must be 0..2^32');
  if (!isU32(t) || t < 1)
    throw new Error('"t" (iterations) must be 1..2^32');
  if (onProgress !== void 0 && typeof onProgress !== "function")
    throw new Error('"onProgress" must be a function');
  anumber3(asyncTick, "asyncTick");
  if (!isU32(m) || m < 8 * p)
    throw new Error('"m" (memory) must be at least 8*p bytes');
  if (version !== 16 && version !== 19)
    throw new Error('"version" must be 0x10 or 0x13, got ' + version);
  return merged;
}
function argon2InitialHash(password, salt, type, opts) {
  const ownedInputs = [];
  const BUF = new Uint32Array(1);
  const BUF8 = u8(BUF);
  let h;
  let H0;
  let succeeded = false;
  const rememberOwned = (input, bytes) => {
    if (typeof input === "string")
      ownedInputs.push(bytes);
    return bytes;
  };
  try {
    const passwordBytes = rememberOwned(password, kdfInputToBytes(password, "password"));
    const saltBytes = rememberOwned(salt, kdfInputToBytes(salt, "salt"));
    if (!isU32(passwordBytes.length))
      throw new Error('"password" must be less of length 1..4Gb');
    if (!isU32(saltBytes.length) || saltBytes.length < 8)
      throw new Error('"salt" must be of length 8..4Gb');
    if (!Object.values(AT).includes(type))
      throw new Error('"type" was invalid');
    let { p, dkLen, m, t, version, key: key2, personalization, maxmem, onProgress, asyncTick } = argon2Opts(opts);
    const keyInput = key2;
    key2 = rememberOwned(keyInput, abytesOrZero(keyInput, "key"));
    const personalizationInput = personalization;
    personalization = rememberOwned(personalizationInput, abytesOrZero(personalizationInput, "personalization"));
    h = blake2b.create();
    for (let item of [p, dkLen, m, t, version, type]) {
      BUF[0] = swap8IfBE(item);
      h.update(BUF8);
    }
    for (let i of [passwordBytes, saltBytes, key2, personalization]) {
      BUF[0] = swap8IfBE(i.length);
      h.update(BUF8).update(i);
    }
    H0 = new Uint32Array(18);
    h.digestInto(u8(H0));
    succeeded = true;
    return { H0, p, dkLen, m, t, version, maxmem, onProgress, asyncTick };
  } finally {
    if (h)
      h.destroy();
    clean2(BUF, ...ownedInputs);
    if (!succeeded && H0)
      clean2(H0);
  }
}
function argon2Init(password, salt, type, opts) {
  const { H0, p, dkLen, m, t, version, maxmem, onProgress, asyncTick } = argon2InitialHash(password, salt, type, opts);
  try {
    const lanes = p;
    const mP = 4 * p * Math.floor(m / (ARGON2_SYNC_POINTS * p));
    const laneLen = Math.floor(mP / p);
    const segmentLen = Math.floor(laneLen / ARGON2_SYNC_POINTS);
    const memUsed = mP * 1024;
    if (!isU32(maxmem))
      throw new Error('"maxmem" expected <2**32, got ' + maxmem);
    if (memUsed > maxmem)
      throw new Error('"maxmem" limit was hit: memUsed(mP*1024)=' + memUsed + ", maxmem=" + maxmem);
    const B = new Uint32Array(memUsed / 4);
    for (let l = 0; l < p; l++) {
      const i = 256 * laneLen * l;
      H0[17] = swap8IfBE(l);
      H0[16] = swap8IfBE(0);
      B.set(swap32IfBE(u32(Hp(H0, 1024))), i);
      H0[16] = swap8IfBE(1);
      B.set(swap32IfBE(u32(Hp(H0, 1024))), i + 256);
    }
    let perBlock = () => {
    };
    if (onProgress) {
      const totalBlock = t * ARGON2_SYNC_POINTS * p * segmentLen - 2 * p;
      const callbackPer = Math.max(Math.floor(totalBlock / 1e4), 1);
      let blockCnt = 0;
      perBlock = () => {
        blockCnt++;
        if (onProgress && (!(blockCnt % callbackPer) || blockCnt === totalBlock))
          onProgress(blockCnt / totalBlock);
      };
    }
    return { type, mP, p, t, version, B, laneLen, lanes, segmentLen, dkLen, perBlock, asyncTick };
  } finally {
    clean2(H0);
  }
}
function argon2Output(B, p, laneLen, dkLen) {
  const B_final = new Uint32Array(256);
  for (let l = 0; l < p; l++)
    for (let j = 0; j < 256; j++)
      B_final[j] ^= B[256 * (laneLen * l + laneLen - 1) + j];
  const res = Hp(swap32IfBE(B_final), dkLen);
  clean2(B, B_final);
  return res;
}
function* argon2Blocks(ctx, address) {
  const { type, mP, p, t, version, B, laneLen, lanes, segmentLen, perBlock } = ctx;
  address[256 + 6] = mP;
  address[256 + 8] = t;
  address[256 + 10] = type;
  for (let r = 0; r < t; r++) {
    const needXor = r !== 0 && version === 19;
    address[256 + 0] = r;
    for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
      address[256 + 4] = s;
      const dataIndependent = type == AT.Argon2i || type == AT.Argon2id && r === 0 && s < 2;
      for (let l = 0; l < p; l++) {
        address[256 + 2] = l;
        address[256 + 12] = 0;
        let startPos = 0;
        if (r === 0 && s === 0) {
          startPos = 2;
          if (dataIndependent) {
            address[256 + 12]++;
            block(address, 256, 2 * 256, 0, false);
            block(address, 0, 2 * 256, 0, false);
          }
        }
        let offset = l * laneLen + s * segmentLen + startPos;
        for (let index = startPos; index < segmentLen; index++, offset++) {
          perBlock();
          const prev = offset % laneLen ? offset - 1 : offset + laneLen - 1;
          let randL, randH;
          if (dataIndependent) {
            let i128 = index % 128;
            if (i128 === 0) {
              address[256 + 12]++;
              block(address, 256, 2 * 256, 0, false);
              block(address, 0, 2 * 256, 0, false);
            }
            randL = address[2 * i128];
            randH = address[2 * i128 + 1];
          } else {
            const T = 256 * prev;
            randL = B[T];
            randH = B[T + 1];
          }
          const refLane = r === 0 && s === 0 ? l : randH % lanes;
          const refPos = indexAlpha(r, s, laneLen, segmentLen, index, randL, refLane == l);
          const refBlock = laneLen * refLane + refPos;
          block(B, 256 * prev, 256 * refBlock, offset * 256, needXor);
          yield;
        }
      }
    }
  }
  clean2(address);
}
function argon2(type, password, salt, opts) {
  const ctx = argon2Init(password, salt, type, opts);
  const blocks = argon2Blocks(ctx, new Uint32Array(3 * 256));
  while (!blocks.next().done) {
  }
  return argon2Output(ctx.B, ctx.p, ctx.laneLen, ctx.dkLen);
}
var argon2id = (password, salt, opts = {}) => argon2(AT.Argon2id, password, salt, opts);

// src/lib/lexis/kdf.ts
var DEFAULT_KDF = {
  memoryKiB: 4096,
  iterations: 2,
  parallelism: 1
};
var VAULT_KDF = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1
};
var LIMITS = {
  memoryKiB: { min: 8, max: 16384 },
  iterations: { min: 1, max: 4 },
  parallelism: { min: 1, max: 2 }
};
function clampInt(value, min, max, fallback) {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}
function clampKdf(input) {
  const parallelism = clampInt(input?.parallelism, LIMITS.parallelism.min, LIMITS.parallelism.max, DEFAULT_KDF.parallelism);
  const minMemory = 8 * parallelism;
  const memoryKiB = Math.max(
    clampInt(input?.memoryKiB, LIMITS.memoryKiB.min, LIMITS.memoryKiB.max, DEFAULT_KDF.memoryKiB),
    minMemory
  );
  const iterations = clampInt(input?.iterations, LIMITS.iterations.min, LIMITS.iterations.max, DEFAULT_KDF.iterations);
  return { memoryKiB, iterations, parallelism };
}
function clampOffer(input) {
  return { ...clampKdf(input), honey: input?.honey === true };
}
function clampVaultKdf(input) {
  return {
    memoryKiB: clampInt(input?.memoryKiB, 8, 262144, VAULT_KDF.memoryKiB),
    iterations: clampInt(input?.iterations, 1, 8, VAULT_KDF.iterations),
    parallelism: clampInt(input?.parallelism, 1, 1, VAULT_KDF.parallelism)
  };
}
function encodeKdf(params) {
  const c = clampKdf(params);
  return new Uint8Array([c.memoryKiB >> 8 & 255, c.memoryKiB & 255, c.iterations, c.parallelism]);
}
function decodeKdf(bytes, offset) {
  const memoryKiB = (bytes[offset] << 8 | bytes[offset + 1]) >>> 0;
  return clampKdf({
    memoryKiB,
    iterations: bytes[offset + 2],
    parallelism: bytes[offset + 3]
  });
}
var FEATURE_HONEY = 1;
function featureByte(honey) {
  return honey ? FEATURE_HONEY : 0;
}
function honeyFromFeatures(features) {
  return (features & FEATURE_HONEY) !== 0;
}
function deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params) {
  const c = clampKdf(params);
  const t0 = Date.now();
  const key2 = argon2id(concat(ssE, ssS, u32be(window), new Uint8Array([features & 255])), concat(nonceC, nonceS), {
    t: c.iterations,
    m: c.memoryKiB,
    p: c.parallelism,
    dkLen: 32
  });
  return { key: key2, ms: Math.max(1, Date.now() - t0) };
}
var sessionDeriver = async (ssE, ssS, nonceC, nonceS, window, features, params) => deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params);
function setSessionKeyDeriver(fn) {
  sessionDeriver = fn ?? (async (ssE, ssS, nonceC, nonceS, window, features, params) => deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params));
}
function deriveSessionKeyAsync(ssE, ssS, nonceC, nonceS, window, features, params) {
  return sessionDeriver(ssE, ssS, nonceC, nonceS, window, features, params);
}

// src/lib/lexis/handshake.ts
function currentWindow(now = Date.now()) {
  return Math.floor(now / 1e3 / SPEC.windowSec);
}
var HELLO_CORE = 2 + 65 + 65 + 4 + 16 + 4 + 1;
var SERVER_CORE = 2 + 65 + 65 + 16 + 16 + 4 + 1;
var seenHellos = /* @__PURE__ */ new Map();
var helloByPeer = /* @__PURE__ */ new Map();
var helloByIp = /* @__PURE__ */ new Map();
var HELLO_PEER_CAP = 16;
var HELLO_IP_CAP = 32;
function assertHelloWindow(helloWindow, now = Date.now()) {
  const current = currentWindow(now);
  const into = Math.floor(now / 1e3) % SPEC.windowSec;
  const skew = SPEC.skewSec;
  const prevOk = helloWindow === current - 1 && into < skew;
  const nextOk = helloWindow === current + 1 && into >= SPEC.windowSec - skew;
  if (helloWindow === current || prevOk || nextOk) return;
  throw new LexisError("\u63E1\u624B\u65F6\u95F4\u7A97\u5DF2\u7ECF\u8FC7\u671F");
}
function nonceId(nonce) {
  let hex2 = "";
  for (const b of nonce) hex2 += b.toString(16).padStart(2, "0");
  return hex2;
}
function claimHello(window, nonce, scope) {
  const current = currentWindow();
  for (const key2 of [...seenHellos.keys()]) {
    if (key2 < current - 1 || key2 > current + 1) seenHellos.delete(key2);
  }
  pruneHelloScope(helloByPeer, current);
  pruneHelloScope(helloByIp, current);
  let bag = seenHellos.get(window);
  if (!bag) {
    bag = /* @__PURE__ */ new Set();
    seenHellos.set(window, bag);
  }
  const id = nonceId(nonce);
  if (bag.has(id)) throw new LexisError("\u63E1\u624B\u88AB\u91CD\u653E");
  if (scope?.peer) bumpHelloScope(helloByPeer, scope.peer, window, HELLO_PEER_CAP, "\u8FD9\u4E2A\u8282\u70B9\u7684\u63E1\u624B\u592A\u5BC6");
  if (scope?.ip) bumpHelloScope(helloByIp, scope.ip, window, HELLO_IP_CAP, "\u8FD9\u4E2A\u5730\u5740\u7684\u63E1\u624B\u592A\u5BC6");
  if (bag.size >= 4096) throw new LexisError("\u8FD9\u4E2A\u65F6\u95F4\u7A97\u7684\u63E1\u624B\u592A\u591A");
  bag.add(id);
}
function pruneHelloScope(map, current) {
  for (const [key2, row] of map) {
    if (row.window < current - 1 || row.window > current + 1) map.delete(key2);
  }
}
function bumpHelloScope(map, key2, window, cap, message) {
  const prev = map.get(key2);
  const row = prev && prev.window === window ? prev : { window, n: 0 };
  if (row.n >= cap) throw new LexisError(message);
  row.n += 1;
  map.set(key2, row);
}
async function tokenMac(token, body) {
  return (await hmac(utf8(token), concat(utf8("lexis-admit-v1"), body))).subarray(0, 16);
}
async function publicConfirm(label, tr) {
  return (await hmac(utf8("lexis-pub-confirm-v1"), concat(utf8(label), tr))).subarray(0, 16);
}
function transcript(parts) {
  return concat(
    utf8("LEXIS2"),
    parts.ephC,
    parts.ephS,
    parts.ltC,
    parts.ltS,
    u32be(parts.window),
    parts.nonceC,
    parts.nonceS,
    parts.kdf,
    new Uint8Array([parts.features & 255])
  );
}
async function edgeStart(edge, now = Date.now(), offer, token = "") {
  const wanted = clampOffer(offer);
  const eph = await createIdentity();
  const ltRaw = unb64(edge.publicRawB64);
  assertPoint(ltRaw, "\u5185\u7F51\u7AEF");
  assertPoint(eph.publicRaw, "\u5185\u7F51\u7AEF\u4E34\u65F6");
  const nonceC = crypto.getRandomValues(new Uint8Array(16));
  const window = currentWindow(now);
  let blob = concat(
    new Uint8Array([1, 1]),
    eph.publicRaw,
    ltRaw,
    u32be(window),
    nonceC,
    encodeKdf(wanted),
    new Uint8Array([featureByte(wanted.honey)])
  );
  if (token) blob = concat(blob, await tokenMac(token, blob));
  const helloWire = await encodeStatic(blob);
  return { eph, nonceC, window, helloWire, ltRaw };
}
function parseHello(buf2) {
  if (buf2.length !== HELLO_CORE && buf2.length !== HELLO_CORE + 16) throw new LexisError("\u5BA2\u6237\u7AEF\u95EE\u5019\u957F\u5EA6\u4E0D\u5BF9");
  if (buf2[0] !== 1 || buf2[1] !== 1) throw new LexisError("\u5BA2\u6237\u7AEF\u95EE\u5019\u7248\u672C\u4E0D\u5BF9");
  const mac = buf2.length === HELLO_CORE + 16 ? buf2.slice(HELLO_CORE) : null;
  const ephRaw = buf2.slice(2, 67);
  const ltRaw = buf2.slice(67, 132);
  const window = buf2[132] << 24 | buf2[133] << 16 | buf2[134] << 8 | buf2[135];
  const nonce = buf2.slice(136, 152);
  const kdf = decodeKdf(buf2, 152);
  const features = buf2[156];
  assertPoint(ephRaw, "\u5BF9\u7AEF\u4E34\u65F6");
  assertPoint(ltRaw, "\u5BF9\u7AEF\u957F\u671F");
  return { ephRaw, ltRaw, window: window >>> 0, nonce, kdf, features, mac };
}
function parseServer(buf2) {
  if (buf2.length !== SERVER_CORE && buf2.length !== SERVER_CORE + 16) throw new LexisError("\u670D\u52A1\u7AEF\u95EE\u5019\u957F\u5EA6\u4E0D\u5BF9");
  if (buf2[0] !== 1 || buf2[1] !== 2) throw new LexisError("\u670D\u52A1\u7AEF\u95EE\u5019\u7248\u672C\u4E0D\u5BF9");
  const mac = buf2.length === SERVER_CORE + 16 ? buf2.slice(SERVER_CORE) : null;
  const ephRaw = buf2.slice(2, 67);
  const ltRaw = buf2.slice(67, 132);
  const nonce = buf2.slice(132, 148);
  const confirm = buf2.slice(148, 164);
  const kdf = decodeKdf(buf2, 164);
  const features = buf2[168];
  assertPoint(ephRaw, "\u95F8\u95E8\u4E34\u65F6");
  assertPoint(ltRaw, "\u95F8\u95E8\u957F\u671F");
  return { ephRaw, ltRaw, nonce, confirm, kdf, features, mac };
}
async function gateRespond(gate, peerRawB64, helloWire, opts = {}) {
  const raw = await decodeStatic(helloWire);
  const hello = parseHello(raw);
  assertHelloWindow(hello.window, opts.now ?? Date.now());
  const token = opts.token || "";
  if (token) {
    if (!hello.mac) throw new LexisError("\u7F3A\u5C11\u63E1\u624B\u53E3\u4EE4");
    const expect = await tokenMac(token, raw.slice(0, HELLO_CORE));
    if (!timingSafeEqual(expect, hello.mac)) throw new LexisError("\u63E1\u624B\u53E3\u4EE4\u4E0D\u5BF9");
  } else if (hello.mac) {
    throw new LexisError("\u5BF9\u7AEF\u5E26\u4E86\u53E3\u4EE4\uFF0C\u8FD9\u8FB9\u6CA1\u6709");
  }
  const pinned = unb64(peerRawB64);
  if (!timingSafeEqual(hello.ltRaw, pinned)) {
    throw new LexisError("\u5185\u7F51\u7AEF\u957F\u671F\u516C\u94A5\u548C\u95F8\u95E8\u4E0A\u7684\u7ED1\u5B9A\u4E0D\u4E00\u81F4");
  }
  claimHello(hello.window, hello.nonce, { peer: opts.peerId || "", ip: opts.sourceIp || "" });
  const ephS = await createIdentity();
  const ltS = unb64(gate.publicRawB64);
  const nonceS = crypto.getRandomValues(new Uint8Array(16));
  const ssE = await ecdh(await importPrivateJwk(ephS.privateJwk), await importRawPublic(hello.ephRaw));
  const ssS = await ecdh(await importPrivateJwk(gate.privateJwk), await importRawPublic(hello.ltRaw));
  const agreed = clampKdf(opts.kdf ?? hello.kdf);
  const kdfBytes = encodeKdf(agreed);
  const features = hello.features & 255;
  const derived = await deriveSessionKeyAsync(ssE, ssS, hello.nonce, nonceS, hello.window, features, agreed);
  const sk = derived.key;
  const tr = transcript({
    ephC: hello.ephRaw,
    ephS: ephS.publicRaw,
    ltC: hello.ltRaw,
    ltS,
    window: hello.window,
    nonceC: hello.nonce,
    nonceS,
    kdf: kdfBytes,
    features
  });
  const confirmS = await publicConfirm("lexis-srv-pub-v1", tr);
  const expectFinish = await publicConfirm("lexis-cli-pub-v1", tr);
  let blob = concat(new Uint8Array([1, 2]), ephS.publicRaw, ltS, nonceS, confirmS, kdfBytes, new Uint8Array([features]));
  if (token) blob = concat(blob, await tokenMac(token, blob));
  const serverWire = await encodeStatic(blob);
  return {
    sk,
    window: hello.window,
    ephC: hello.ephRaw,
    ephS: ephS.publicRaw,
    ltC: hello.ltRaw,
    ltS,
    nonceC: hello.nonce,
    nonceS,
    serverWire,
    expectFinish,
    kdf: agreed,
    features
  };
}
async function edgeFinish(edge, pending, gateRawB64, serverWire, token = "") {
  const raw = await decodeStatic(serverWire);
  const server = parseServer(raw);
  const pinned = unb64(gateRawB64);
  if (!timingSafeEqual(server.ltRaw, pinned)) {
    throw new LexisError("\u95F8\u95E8\u957F\u671F\u516C\u94A5\u548C\u5185\u7F51\u7AEF\u4E0A\u7684\u7ED1\u5B9A\u4E0D\u4E00\u81F4");
  }
  if (token) {
    if (!server.mac) throw new LexisError("\u95F8\u95E8\u6CA1\u6709\u5E26\u56DE\u53E3\u4EE4");
    const expectMac = await tokenMac(token, raw.slice(0, SERVER_CORE));
    if (!timingSafeEqual(expectMac, server.mac)) throw new LexisError("\u63E1\u624B\u53E3\u4EE4\u4E0D\u5BF9");
  } else if (server.mac) {
    throw new LexisError("\u5BF9\u7AEF\u5E26\u4E86\u53E3\u4EE4\uFF0C\u8FD9\u8FB9\u6CA1\u6709");
  }
  const ssE = await ecdh(
    await importPrivateJwk(pending.eph.privateJwk),
    await importRawPublic(server.ephRaw)
  );
  const ssS = await ecdh(
    await importPrivateJwk(edge.privateJwk),
    await importRawPublic(server.ltRaw)
  );
  const features = server.features & 255;
  const derived = await deriveSessionKeyAsync(ssE, ssS, pending.nonceC, server.nonce, pending.window, features, server.kdf);
  const sk = derived.key;
  const tr = transcript({
    ephC: pending.eph.publicRaw,
    ephS: server.ephRaw,
    ltC: pending.ltRaw,
    ltS: server.ltRaw,
    window: pending.window,
    nonceC: pending.nonceC,
    nonceS: server.nonce,
    kdf: encodeKdf(server.kdf),
    features
  });
  const expectS = await publicConfirm("lexis-srv-pub-v1", tr);
  if (!timingSafeEqual(expectS, server.confirm)) {
    throw new LexisError("\u95F8\u95E8\u786E\u8BA4\u6807\u8BB0\u5BF9\u4E0D\u4E0A");
  }
  const confirmC = await publicConfirm("lexis-cli-pub-v1", tr);
  const finishWire = await encodeStatic(concat(new Uint8Array([1, 3]), confirmC));
  return {
    sk,
    finishWire,
    window: pending.window,
    kdf: server.kdf,
    honey: honeyFromFeatures(features),
    kdfMs: derived.ms
  };
}
async function gateAccept(pending, finishWire) {
  const buf2 = await decodeStatic(finishWire);
  if (buf2.length !== 18 || buf2[0] !== 1 || buf2[1] !== 3) throw new LexisError("\u7ED3\u675F\u63E1\u624B\u7684\u62A5\u6587\u4E0D\u5BF9");
  const confirm = buf2.slice(2);
  if (!timingSafeEqual(confirm, pending.expectFinish)) {
    throw new LexisError("\u5185\u7F51\u7AEF\u786E\u8BA4\u6807\u8BB0\u5BF9\u4E0D\u4E0A");
  }
}
async function openSession(opts) {
  const lexicon = await sessionLexicon(opts.sk, opts.window);
  const inverse = invertLexicon(lexicon);
  const skFp = await fingerprintOf(opts.sk);
  return {
    sk: opts.sk,
    skFp,
    window: opts.window,
    lexicon,
    inverse,
    counters: { e2g: 0, g2e: 0 },
    seen: { e2g: 0, g2e: 0 },
    helloWire: opts.helloWire,
    serverWire: opts.serverWire,
    finishWire: opts.finishWire,
    edgeName: opts.edge.name,
    gateName: opts.gate.name,
    edgeFp: opts.edge.fingerprint,
    gateFp: opts.gate.fingerprint,
    kdf: opts.kdf,
    honey: opts.honey,
    kdfMs: opts.kdfMs,
    program: opts.program ?? null
  };
}

// src/lib/lexis/records.ts
var RECORD = {
  heartbeat: 1,
  data: 2,
  open: 3,
  close: 4,
  credit: 5,
  rekey: 6
};
function encodeRecord(type, conn, seq, payload) {
  const out = new Uint8Array(11 + payload.length);
  out[0] = type & 255;
  out.set(u32be(conn), 1);
  out.set(u32be(seq), 5);
  out[9] = payload.length >> 8 & 255;
  out[10] = payload.length & 255;
  out.set(payload, 11);
  return out;
}
function decodeRecord(frame) {
  if (frame.length < 11) throw new Error("\u5185\u5C42\u5E27\u8FC7\u77ED");
  const len = readU16(frame, 9);
  if (frame.length < 11 + len) throw new Error("\u5185\u5C42\u5E27\u88AB\u622A\u65AD");
  return {
    type: frame[0],
    conn: readU32(frame, 1),
    seq: readU32(frame, 5),
    payload: frame.slice(11, 11 + len)
  };
}
function heartbeatPayload(now = Date.now()) {
  return utf8(`hb ${now}`);
}

// src/lib/lexis/honey.ts
var POLY = 1n << 128n | 0x87n;
var MASK = (1n << 128n) - 1n;
function add2(a, b) {
  return a ^ b;
}
function mul(a, b) {
  let res = 0n;
  let x = a;
  let y = b;
  while (y > 0n) {
    if (y & 1n) res ^= x;
    x <<= 1n;
    if (x & 1n << 128n) x ^= POLY;
    y >>= 1n;
  }
  return res & MASK;
}
function fromBytes(bytes) {
  let n = 0n;
  for (const b of bytes) n = n << 8n | BigInt(b);
  return n & MASK;
}
function toBytes(n) {
  const out = new Uint8Array(16);
  let x = n & MASK;
  for (let i = 15; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
function xor16(a, b) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) out[i] = a[i] ^ b[i];
  return out;
}
function horner(coeffs, x) {
  let result = 0n;
  for (let i = coeffs.length - 1; i >= 0; i -= 1) result = add2(mul(result, x), coeffs[i]);
  return result;
}
async function lane(key2, salt, label) {
  const mac = await hmac(key2, concat(salt, utf8(label)));
  return mac.subarray(0, 16);
}
function indicesFrom(block2) {
  const out = [0, 0, 0, 0];
  for (let i = 0; i < 4; i += 1) {
    const v = (block2[i * 2] << 8 | block2[i * 2 + 1]) & 65535;
    out[i] = v % SPEC.lexiconSize;
  }
  return out;
}
async function evalHoney(program, key2) {
  const x = await lane(key2, program.salt, "x");
  const r = await lane(key2, program.salt, "r");
  const y = horner(program.coeffs.map(fromBytes), fromBytes(x));
  return xor16(toBytes(y), r);
}
async function honeyPhrase(key2, window, seed, program) {
  const lex = await sessionLexicon(key2, window);
  const block2 = program ? await evalHoney(program, key2) : await hkdf(key2, u32be(window), seed.length ? seed : utf8("honey"), 16);
  const idx = indicesFrom(block2);
  return `the ${lex[idx[0]]} and our ${lex[idx[1]]} that its ${lex[idx[2]]} and the ${lex[idx[3]]}`;
}
function scalarFromSeed(seed) {
  let hex2 = "";
  for (const b of seed) hex2 += b.toString(16).padStart(2, "0");
  let n = p256.Point.Fn.create(BigInt(`0x${hex2}`));
  if (n === 0n) n = 1n;
  return p256.Point.Fn.toBytes(n);
}
function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}
async function stretch(passphrase, salt, params) {
  const c = clampVaultKdf(params);
  return argon2id(utf8(passphrase), salt, { t: c.iterations, m: c.memoryKiB, p: c.parallelism, dkLen: 32 });
}
async function openIdentityVault(vault, passphrase) {
  const dk = await stretch(passphrase, vault.salt, vault.kdf);
  const lo = await evalHoney(vault.lo, dk);
  const hi = await evalHoney(vault.hi, dk);
  const joined = new Uint8Array(32);
  joined.set(lo, 0);
  joined.set(hi, 16);
  const secret = scalarFromSeed(joined);
  const pub = p256.getPublicKey(secret, false);
  const x = b64url(pub.subarray(1, 33));
  const y = b64url(pub.subarray(33, 65));
  const d = b64url(secret);
  return identityFromJwks(
    { kty: "EC", crv: "P-256", x, y, ext: true },
    { kty: "EC", crv: "P-256", x, y, d, ext: true }
  );
}
function programFromStored(raw) {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw;
  if (typeof rec.saltB64 !== "string" || !Array.isArray(rec.coeffsB64) || rec.coeffsB64.length < 1 || rec.coeffsB64.length > 8) {
    return null;
  }
  try {
    const salt = unb64(rec.saltB64);
    if (salt.length !== 16) return null;
    const coeffs = rec.coeffsB64.map((item) => {
      if (typeof item !== "string") throw new Error("\u7CFB\u6570\u4E0D\u5BF9");
      const bytes = unb64(item);
      if (bytes.length !== 16) throw new Error("\u7CFB\u6570\u4E0D\u5BF9");
      return bytes;
    });
    return { salt, coeffs };
  } catch {
    return null;
  }
}
function vaultFromStored(raw) {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw;
  if (typeof rec.saltB64 !== "string") return null;
  const lo = programFromStored(rec.lo);
  const hi = programFromStored(rec.hi);
  if (!lo || !hi) return null;
  try {
    const salt = unb64(rec.saltB64);
    if (salt.length < 8) return null;
    return {
      salt,
      kdf: clampVaultKdf({ memoryKiB: rec.memoryKiB, iterations: rec.iterations, parallelism: rec.parallelism }),
      lo,
      hi
    };
  } catch {
    return null;
  }
}
function blendBytes(real, cover, takeReal) {
  const m = takeReal & 1;
  const inv = 1 - m;
  const n = m * real.length + inv * cover.length;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    const a = i < real.length ? real[i] : 0;
    const b = i < cover.length ? cover[i] : 0;
    out[i] = a * m + b * inv & 255;
  }
  return out;
}

// src/lib/lexis/seal.ts
function mask24(mac) {
  return (mac[0] << 16 | mac[1] << 8 | mac[2]) >>> 0;
}
async function seal(input) {
  const { key: key2, lexicon, counter, window, direction, plaintext } = input;
  if (counter < 1 || counter > 16777215) throw new LexisError("\u8BA1\u6570\u5668\u8D85\u51FA 24 \u4F4D\u8303\u56F4");
  if (lexicon.length !== SPEC.lexiconSize) throw new LexisError("\u8BCD\u8868\u957F\u5EA6\u4E0D\u5BF9");
  const tag = randomBytes(SPEC.macBytes);
  const framed = concat(u16be(plaintext.length), plaintext, tag);
  const chunks = bytesToChunks(framed);
  const ks = await hkdfStream(
    key2,
    concat(utf8(`lexis-body-v1|${direction}|${window}|`), u32be(counter)),
    "LEXIS-KS-v1",
    chunks.length * 2
  );
  const body = chunks.map((c, i) => {
    const ks12 = (ks[i * 2] << 8 | ks[i * 2 + 1]) & 4095;
    return lexicon[(c + ks12) % SPEC.lexiconSize];
  });
  const mask = mask24(
    await hmac(key2, utf8(`lexis-counter-mask-v1|${direction}|${window}`))
  );
  const masked = (counter ^ mask) & 16777215;
  const c0 = lexicon[masked >> 12 & 4095];
  const c1 = lexicon[masked & 4095];
  return dress([c0, c1, ...body], counter);
}
async function recover(input) {
  const { key: key2, inverse, window, direction, prose } = input;
  const words = undress(prose);
  if (words.length < 3) throw new LexisError("\u62A5\u6587\u592A\u77ED\uFF0C\u4E0D\u50CF\u4E00\u5E27\u8BCD\u9699");
  let missing = false;
  const take = (w) => {
    const idx = inverse.get(w);
    if (idx === void 0) {
      missing = true;
      return 0;
    }
    return idx;
  };
  const mask = mask24(await hmac(key2, utf8(`lexis-counter-mask-v1|${direction}|${window}`)));
  const masked = (take(words[0]) & 4095) << 12 | take(words[1]) & 4095;
  const counter = (masked ^ mask) & 16777215;
  const bodyWords = words.slice(2);
  const ks = await hkdfStream(
    key2,
    concat(utf8(`lexis-body-v1|${direction}|${window}|`), u32be(counter)),
    "LEXIS-KS-v1",
    bodyWords.length * 2
  );
  const chunks = bodyWords.map((w, i) => {
    const ks12 = (ks[i * 2] << 8 | ks[i * 2 + 1]) & 4095;
    return (take(w) - ks12 + SPEC.lexiconSize) % SPEC.lexiconSize;
  });
  return { missing, counter, raw: chunksToBytes(chunks) };
}
async function open(input) {
  const { key: key2, window, prose, lastSeen } = input;
  const honey = input.honey === true;
  const { missing, counter, raw } = await recover(input);
  const seed = raw.length ? raw : utf8(prose);
  const coverOf = () => honeyPhrase(key2, window, seed, input.program);
  const release = async (takeReal, real) => {
    const cover = honey ? utf8(await coverOf()) : real;
    const bit = honey ? takeReal & 1 : 1;
    return {
      counter: bit * counter + (1 - bit) * lastSeen,
      plaintext: blendBytes(real, cover, bit),
      honey: honey && bit === 0
    };
  };
  if (missing || raw.length < 2 + SPEC.macBytes) {
    if (!honey) throw new LexisError(missing ? "\u6709\u8BCD\u4E0D\u5728\u672C\u65F6\u95F4\u7A97\u7684\u8BCD\u8868\u91CC\u3002\u5BC6\u94A5\u6216\u65F6\u95F4\u7A97\u4E0D\u4E00\u81F4\uFF0C\u6216\u62A5\u6587\u88AB\u6539\u8FC7\u3002" : "\u6B63\u6587\u957F\u5EA6\u4E0D\u591F");
    return release(0, new Uint8Array());
  }
  const len = readU16(raw, 0);
  if (2 + len + SPEC.macBytes > raw.length) {
    if (!honey) throw new LexisError("\u6B63\u6587\u5B57\u6BB5\u88AB\u622A\u65AD");
    return release(0, new Uint8Array());
  }
  const plaintext = raw.slice(2, 2 + len);
  if (counter < 1 || counter <= lastSeen) {
    if (!honey) throw new LexisError(counter < 1 ? "\u8BA1\u6570\u5668\u65E0\u6548" : "\u8BA1\u6570\u5668\u6CA1\u6709\u524D\u8FDB\uFF0C\u6309\u56DE\u653E\u4E22\u5F03");
    return release(0, plaintext);
  }
  return release(1, plaintext);
}

// src/agent/frame.ts
var zstdReady = null;
function ensureZstd() {
  if (!zstdReady) {
    zstdReady = (async () => {
      const here = dirname(fileURLToPath(import.meta.url));
      const buf2 = readFileSync(join(here, "zstd.wasm"));
      const wasm = buf2.buffer.slice(buf2.byteOffset, buf2.byteOffset + buf2.byteLength);
      Module.init(wasm);
      await waitInitialized();
    })();
  }
  return zstdReady;
}
async function packRecord(data, pref) {
  if (!pref.enabled) return concat(new Uint8Array([0]), data);
  await ensureZstd();
  const level = Math.min(19, Math.max(1, pref.level || 3));
  const zipped = compress(data, level);
  if (zipped.length < data.length && zipped.length >= 4) return concat(new Uint8Array([1]), zipped);
  return concat(new Uint8Array([0]), data);
}
async function unpackRecord(bytes) {
  if (bytes.length >= 1 && bytes[0] === 0) return bytes.subarray(1);
  if (bytes.length >= 5 && bytes[0] === 1) {
    await ensureZstd();
    return decompress(bytes.subarray(1));
  }
  throw new Error("\u660E\u6587\u7C7B\u578B\u5B57\u8282\u4E0D\u8BA4\u8BC6");
}
function parseOpen(text) {
  const raw = String(text || "").trim();
  const relay = raw.match(/^relay\s+(\S+)\s+([\s\S]+)$/);
  if (relay) {
    const rest = relay[2].trim();
    const inner = parseOpen(rest);
    return { relay: relay[1], rest, expose: null, udp: inner.udp, host: inner.host, port: inner.port };
  }
  const expose = raw.match(/^expose\s+(\S+)$/);
  if (expose) return { relay: null, rest: raw, expose: expose[1], udp: false, host: "", port: 0 };
  const cmd = raw.match(/^(tcp|udp)\s+(\S+)\s+(\d+)$/);
  if (!cmd) return { relay: null, rest: raw, expose: null, udp: false, host: "", port: 0 };
  return {
    relay: null,
    rest: raw,
    expose: null,
    udp: cmd[1] === "udp",
    host: cmd[2],
    port: Number(cmd[3])
  };
}
function hopCount(text) {
  let n = 0;
  let rest = text.trim();
  while (rest.startsWith("relay ")) {
    n += 1;
    rest = rest.replace(/^relay\s+\S+\s+/, "");
  }
  return n;
}
var HANDSHAKE_CAP = 64 * 1024;
var FRAME_CAP = 4 * 1024 * 1024;
var LinePipe = class {
  constructor(socket) {
    this.socket = socket;
    socket.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      if (this.buf.length > this.cap) {
        this.fail(new Error("\u8BCD\u8868\u7F13\u51B2\u8FC7\u5927"));
        return;
      }
      this.pump();
    });
    socket.on("error", (err2) => this.fail(err2));
    socket.on("close", () => this.fail(new Error("\u8FDE\u63A5\u5173\u95ED")));
  }
  socket;
  buf = Buffer.alloc(0);
  waiters = [];
  dead = null;
  cap = HANDSHAKE_CAP;
  setCap(n) {
    this.cap = n;
  }
  fail(err2) {
    if (!this.dead) this.dead = err2;
    while (this.waiters.length) {
      const waiter = this.waiters.shift();
      waiter?.(this.dead);
    }
    this.socket.destroy();
  }
  pump() {
    while (this.waiters.length) {
      const nl = this.buf.indexOf(10);
      if (nl < 0) return;
      const line = this.buf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      this.buf = this.buf.subarray(nl + 1);
      if (!line) continue;
      const waiter = this.waiters.shift();
      waiter?.(line);
    }
  }
  write(prose) {
    const body = Buffer.from(`${prose}
`, "utf8");
    return new Promise((resolve, reject) => {
      this.socket.write(body, (err2) => err2 ? reject(err2) : resolve());
    });
  }
  read(timeoutMs = 0) {
    if (this.dead && this.buf.indexOf(10) < 0) return Promise.reject(this.dead);
    const nl = this.buf.indexOf(10);
    if (nl >= 0) {
      const line = this.buf.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      this.buf = this.buf.subarray(nl + 1);
      if (!line) return this.read(timeoutMs);
      return Promise.resolve(line);
    }
    return new Promise((resolve, reject) => {
      let timer = null;
      const done = (value) => {
        if (timer) clearTimeout(timer);
        if (value instanceof Error) reject(value);
        else resolve(value);
      };
      if (timeoutMs > 0) timer = setTimeout(() => this.fail(new Error("\u63E1\u624B\u8D85\u65F6")), timeoutMs);
      this.waiters.push(done);
    });
  }
  close() {
    this.socket.end();
  }
};
var WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var WsPipe = class {
  constructor(socket, mask, initial) {
    this.socket = socket;
    this.mask = mask;
    if (initial?.length) this.buf = Buffer.from(initial);
    socket.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.pump();
    });
    socket.on("error", (err2) => this.fail(err2));
    socket.on("close", () => this.fail(new Error("\u8FDE\u63A5\u5173\u95ED")));
    this.pump();
  }
  socket;
  mask;
  buf = Buffer.alloc(0);
  waiters = [];
  dead = null;
  fragments = [];
  early = [];
  cap = HANDSHAKE_CAP;
  fail(err2) {
    if (!this.dead) this.dead = err2;
    while (this.waiters.length) this.waiters.shift()?.(this.dead);
    this.socket.destroy();
  }
  pump() {
    for (; ; ) {
      if (this.buf.length < 2) return;
      const opcode = this.buf[0] & 15;
      const fin = (this.buf[0] & 128) !== 0;
      let len = this.buf[1] & 127;
      let offset = 2;
      if (len === 126) {
        if (this.buf.length < 4) return;
        len = this.buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (this.buf.length < 10) return;
        const big = this.buf.readBigUInt64BE(2);
        if (big > BigInt(this.cap)) {
          this.fail(new Error("WebSocket \u5E27\u8FC7\u5927"));
          return;
        }
        len = Number(big);
        offset = 10;
      }
      if (len > this.cap) {
        this.fail(new Error("WebSocket \u5E27\u8FC7\u5927"));
        return;
      }
      const masked = (this.buf[1] & 128) !== 0;
      if (this.buf.length < offset + (masked ? 4 : 0) + len) return;
      let payload = this.buf.subarray(offset + (masked ? 4 : 0), offset + (masked ? 4 : 0) + len);
      if (masked) {
        const mask = this.buf.subarray(offset, offset + 4);
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      }
      this.buf = this.buf.subarray(offset + (masked ? 4 : 0) + len);
      if (opcode === 8) {
        this.fail(new Error("\u8FDE\u63A5\u5173\u95ED"));
        return;
      }
      if (opcode === 9) {
        void this.socket.write(wsFrame(10, payload, this.mask));
        continue;
      }
      if (opcode === 10) continue;
      if (opcode === 1 || opcode === 2 || opcode === 0) {
        if (opcode !== 0) this.fragments = [];
        this.fragments.push(Buffer.from(payload));
        if (!fin) continue;
        const text = Buffer.concat(this.fragments).toString("utf8").replace(/\r?\n$/, "");
        this.fragments = [];
        if (!text) continue;
        const waiter = this.waiters.shift();
        if (waiter) waiter(text);
        else this.early.push(text);
      }
    }
  }
  setCap(n) {
    this.cap = n;
  }
  write(prose) {
    const frame = wsFrame(1, Buffer.from(prose, "utf8"), this.mask);
    return new Promise((resolve, reject) => {
      this.socket.write(frame, (err2) => err2 ? reject(err2) : resolve());
    });
  }
  read(timeoutMs = 0) {
    if (this.early.length) return Promise.resolve(this.early.shift());
    if (this.dead) return Promise.reject(this.dead);
    return new Promise((resolve, reject) => {
      let timer = null;
      const done = (value) => {
        if (timer) clearTimeout(timer);
        if (value instanceof Error) reject(value);
        else resolve(value);
      };
      if (timeoutMs > 0) timer = setTimeout(() => this.fail(new Error("\u63E1\u624B\u8D85\u65F6")), timeoutMs);
      this.waiters.push(done);
    });
  }
  close() {
    try {
      this.socket.write(wsFrame(8, Buffer.alloc(0), this.mask));
    } catch {
    }
    this.socket.end();
  }
};
function wsFrame(opcode, payload, mask) {
  const len = payload.length;
  let extra = 0;
  if (len >= 126 && len < 65536) extra = 2;
  else if (len >= 65536) extra = 8;
  const head = 2 + extra + (mask ? 4 : 0);
  const out = Buffer.alloc(head + len);
  out[0] = 128 | opcode;
  if (len < 126) out[1] = (mask ? 128 : 0) | len;
  else if (len < 65536) {
    out[1] = (mask ? 128 : 0) | 126;
    out.writeUInt16BE(len, 2);
  } else {
    out[1] = (mask ? 128 : 0) | 127;
    out.writeBigUInt64BE(BigInt(len), 2);
  }
  let offset = 2 + extra;
  if (mask) {
    const key2 = randomBytes4(4);
    key2.copy(out, offset);
    offset += 4;
    for (let i = 0; i < len; i++) out[offset + i] = payload[i] ^ key2[i & 3];
  } else if (len) payload.copy(out, offset);
  return out;
}
function readHttpHead(socket, cap) {
  return new Promise((resolve, reject) => {
    let buf2 = Buffer.alloc(0);
    const timer = setTimeout(() => cleanup(new Error("WebSocket \u63E1\u624B\u8D85\u65F6")), 1e4);
    const cleanup = (err2, value) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onErr);
      if (err2 || !value) reject(err2 || new Error("WebSocket \u63E1\u624B\u5931\u8D25"));
      else resolve(value);
    };
    const onErr = (err2) => cleanup(err2);
    const onData = (chunk) => {
      buf2 = Buffer.concat([buf2, chunk]);
      if (buf2.length > cap) return cleanup(new Error("WebSocket \u5934\u8FC7\u957F"));
      const at = buf2.indexOf("\r\n\r\n");
      if (at < 0) return;
      cleanup(void 0, { head: buf2.subarray(0, at).toString("utf8"), rest: Buffer.from(buf2.subarray(at + 4)) });
    };
    socket.on("data", onData);
    socket.on("error", onErr);
  });
}
async function wsClientPipe(socket, host, path) {
  const key2 = randomBytes4(16).toString("base64");
  socket.write(
    `GET ${path || "/lexis"} HTTP/1.1\r
Host: ${host}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: ${key2}\r
Sec-WebSocket-Version: 13\r
\r
`
  );
  const { head, rest } = await readHttpHead(socket, 8192);
  const accept = createHash("sha1").update(key2 + WS_GUID).digest("base64");
  if (!/^HTTP\/1\.[01] 101 /.test(head) || !head.toLowerCase().includes(accept.toLowerCase())) {
    socket.destroy();
    throw new Error("\u5BF9\u7AEF\u6CA1\u6709\u5B8C\u6210 WebSocket \u5347\u7EA7");
  }
  return new WsPipe(socket, true, rest);
}
async function wsServerPipe(socket, path) {
  const { head, rest } = await readHttpHead(socket, 16384);
  const lines = head.split("\r\n");
  const request = lines[0] || "";
  const match = request.match(/^GET\s+(\S+)\s+HTTP\/1\.[01]$/);
  const got = match ? match[1].split("?")[0] : "";
  const want = path || "/lexis";
  if (!got || got !== want && got !== `${want}/`) {
    socket.end("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    throw new Error("WebSocket \u8DEF\u5F84\u4E0D\u5BF9");
  }
  const keyLine = lines.find((line) => line.toLowerCase().startsWith("sec-websocket-key:"));
  const key2 = keyLine ? keyLine.slice(keyLine.indexOf(":") + 1).trim() : "";
  if (!key2) {
    socket.destroy();
    throw new Error("\u7F3A\u5C11 WebSocket \u5BC6\u94A5");
  }
  const accept = createHash("sha1").update(key2 + WS_GUID).digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Accept: ${accept}\r
\r
`
  );
  return new WsPipe(socket, false, rest);
}
function tcpPipe(socket) {
  return new LinePipe(socket);
}
function tlsMaterial(certPath, keyPath) {
  const here = dirname(fileURLToPath(import.meta.url));
  return {
    cert: readFileSync(certPath || join(here, "lexis-tls.crt")),
    key: readFileSync(keyPath || join(here, "lexis-tls.key"))
  };
}
function sniName(host) {
  return host && !isIP(host) ? host : void 0;
}
var tlsWarned = false;
function warnUnverifiedTls() {
  if (tlsWarned) return;
  tlsWarned = true;
  console.warn("\u8BCD\u9699\uFF1A\u6CA1\u6709\u6821\u9A8C TLS \u8BC1\u4E66\u3002\u6B63\u5F0F\u90E8\u7F72\u8BF7\u6362\u6210\u81EA\u5DF1\u7684\u8BC1\u4E66\u5E76\u6253\u5F00\u6821\u9A8C\u3002\u8BD5\u9A8C\u8BC1\u4E66\u7684\u79C1\u94A5\u4E0D\u8981\u653E\u8FDB\u5B89\u88C5\u5305\u3002");
}
function dialOuter(opts) {
  const transport = opts.transport || "tcp";
  const tls = transport === "tls" || transport === "wss";
  const ws = transport === "ws" || transport === "wss";
  const name = sniName(opts.wsHost || opts.host);
  if (tls && opts.tlsVerify === false) warnUnverifiedTls();
  return new Promise((resolve, reject) => {
    const raw = opts.openTcp ? opts.openTcp(opts.host, opts.port) : connectTcp({ host: opts.host, port: opts.port });
    const socket = tls ? connectTls({
      socket: raw,
      ...name ? { servername: name } : {},
      rejectUnauthorized: opts.tlsVerify !== false
    }) : raw;
    const fail = (err2) => {
      raw.destroy();
      socket.destroy();
      reject(err2);
    };
    if (opts.timeoutMs && opts.timeoutMs > 0) {
      socket.setTimeout(opts.timeoutMs);
      socket.once("timeout", () => fail(new Error("\u62E8\u53F7\u8D85\u65F6")));
    }
    socket.once("error", fail);
    socket.once(tls ? "secureConnect" : "connect", () => {
      socket.setTimeout(0);
      socket.off("error", fail);
      void (async () => {
        try {
          if (ws) resolve(await wsClientPipe(socket, opts.wsHost || opts.host, opts.path || "/lexis"));
          else resolve(tcpPipe(socket));
        } catch (err2) {
          fail(err2 instanceof Error ? err2 : new Error(String(err2)));
        }
      })();
    });
  });
}
function listenOuter(opts) {
  const transport = opts.transport || "tcp";
  const tlsOn = transport === "tls" || transport === "wss";
  const ws = transport === "ws" || transport === "wss";
  const material = tlsOn ? tlsMaterial(opts.certPath, opts.keyPath) : null;
  const server = tlsOn ? createTls({ cert: material?.cert, key: material?.key }, (socket) => deliver(socket)) : createTcp((socket) => deliver(socket));
  function deliver(socket) {
    socket.on("error", () => socket.destroy());
    const ready = ws ? wsServerPipe(socket, opts.path || "/lexis") : Promise.resolve(tcpPipe(socket));
    opts.onSocket(socket, ready);
  }
  let listenResolve = null;
  const listening = new Promise((resolve) => {
    listenResolve = resolve;
  });
  server.listen(opts.port, opts.host, () => listenResolve?.());
  return {
    close: () => server.close(),
    listening: () => listening
  };
}
async function nodeFromIdentity(identity, role) {
  const ident = await identityFromJwks(identity.publicJwk, identity.privateJwk);
  return {
    id: identity.id,
    name: identity.name || "\u8BCD\u9699",
    role,
    publicJwk: ident.publicJwk,
    privateJwk: ident.privateJwk,
    publicRawB64: identity.publicRawB64 || b64(ident.publicRaw),
    fingerprint: ident.fingerprint,
    pinnedPeerId: null,
    createdAt: 0,
    kdf: null
  };
}
var MuxStream = class {
  constructor(session, id, local) {
    this.session = session;
    this.id = id;
    this.local = local;
  }
  session;
  id;
  local;
  command = "";
  ended = false;
  chunks = [];
  readers = [];
  ack = null;
  ackWaiters = [];
  seq = 1;
  credit = 16;
  creditWait = [];
  waitAck() {
    if (this.ack) return Promise.resolve(this.ack);
    return new Promise((resolve) => this.ackWaiters.push(resolve));
  }
  resolveAck(ack) {
    this.ack = ack;
    while (this.ackWaiters.length) this.ackWaiters.shift()?.(ack);
  }
  queued() {
    return this.chunks.length;
  }
  waitCredit() {
    if (this.credit > 0 || this.ended) return Promise.resolve();
    return new Promise((resolve) => this.creditWait.push(resolve));
  }
  grant(n) {
    this.credit = Math.min(32, this.credit + Math.max(0, n));
    while (this.credit > 0 && this.creditWait.length) this.creditWait.shift()?.();
  }
  push(chunk) {
    const reader = this.readers.shift();
    if (reader) reader(chunk);
    else this.chunks.push(chunk);
  }
  read() {
    const grant = (chunk) => {
      if (chunk) void this.session.sendRecord(RECORD.credit, this.id, ++this.seq, u16be(1)).catch(() => void 0);
      return chunk;
    };
    if (this.chunks.length) return Promise.resolve(grant(this.chunks.shift()));
    if (this.ended) return Promise.resolve(null);
    return new Promise((resolve) => this.readers.push((chunk) => resolve(grant(chunk))));
  }
  async write(chunk) {
    const size = 16 * 1024;
    if (!chunk.length) return;
    for (let i = 0; i < chunk.length; i += size) {
      while (this.credit <= 0 && !this.ended) await this.waitCredit();
      if (this.ended) throw new Error("\u6D41\u5DF2\u5173\u95ED");
      this.credit -= 1;
      const part = chunk.subarray(i, Math.min(chunk.length, i + size));
      await this.session.sendRecord(RECORD.data, this.id, ++this.seq, part);
    }
  }
  accept() {
    return this.session.sendRecord(RECORD.open, this.id, ++this.seq, utf8("ok"));
  }
  reject(reason) {
    const text = `no ${String(reason || "\u62D2\u7EDD").replace(/[\r\n]/g, " ")}`;
    return this.session.sendRecord(RECORD.open, this.id, ++this.seq, utf8(text)).finally(() => this.finish());
  }
  async close() {
    if (this.ended) return;
    this.ended = true;
    try {
      await this.session.sendRecord(RECORD.close, this.id, ++this.seq, utf8("close"));
    } catch {
    }
    this.finish();
  }
  finish() {
    this.ended = true;
    this.session.streams.delete(this.id);
    while (this.readers.length) this.readers.shift()?.(null);
    while (this.creditWait.length) this.creditWait.shift()?.();
    if (!this.ack) this.resolveAck({ ok: false, reason: "\u8FDE\u63A5\u5173\u95ED" });
  }
};
var LexSession = class {
  constructor(pipe, live, initiator, zstd, maxStreams, heartbeatMs, rekeyAt = 16776960) {
    this.pipe = pipe;
    this.initiator = initiator;
    this.zstd = zstd;
    this.maxStreams = maxStreams;
    this.live = live;
    this.sendLive = live;
    this.recvLive = live;
    this.rekeyAt = rekeyAt;
    this.nextId = initiator ? 1 : 2;
    if (heartbeatMs > 0) {
      this.heart = setInterval(() => {
        if (Date.now() - this.lastRx > heartbeatMs * 3) {
          this.shutdown();
          return;
        }
        this.kickRekey();
        void this.sendRecord(RECORD.heartbeat, 0, 0, heartbeatPayload()).catch(() => this.shutdown());
      }, heartbeatMs);
      this.heart.unref?.();
    }
    if (initiator) {
      this.rekeyTimer = setInterval(() => this.kickRekey(), 2e4);
      this.rekeyTimer.unref?.();
    }
  }
  pipe;
  initiator;
  zstd;
  maxStreams;
  streams = /* @__PURE__ */ new Map();
  nextId;
  sendChain = Promise.resolve();
  heart = null;
  closed = false;
  closeWaiters = [];
  onStream = null;
  live;
  sendLive;
  recvLive;
  peerId = "";
  lastRx = Date.now();
  rekeyBusy = false;
  rekeyTimer = null;
  rekeyAt;
  whenClosed() {
    if (this.closed) return Promise.resolve();
    return new Promise((resolve) => this.closeWaiters.push(resolve));
  }
  shutdown() {
    if (this.closed) return;
    this.closed = true;
    if (this.heart) clearInterval(this.heart);
    if (this.rekeyTimer) clearInterval(this.rekeyTimer);
    for (const stream of this.streams.values()) stream.finish();
    this.pipe.close();
    while (this.closeWaiters.length) this.closeWaiters.shift()?.();
  }
  enqueue(fn) {
    const run2 = this.sendChain.then(fn, fn);
    this.sendChain = run2.then(
      () => void 0,
      () => void 0
    );
    return run2;
  }
  sendRecord(type, conn, seq, payload, rekeyNonce) {
    return this.enqueue(async () => {
      if (this.closed) throw new Error("\u4F1A\u8BDD\u5DF2\u5173\u95ED");
      const live = this.sendLive;
      const packed = await packRecord(encodeRecord(type, conn, seq, payload), this.zstd);
      const dir = this.initiator ? "e2g" : "g2e";
      const counter = live.counters[dir] + 1;
      const prose = await seal({
        key: live.sk,
        lexicon: live.lexicon,
        counter,
        window: live.window,
        direction: dir,
        plaintext: packed
      });
      live.counters[dir] = counter;
      await this.pipe.write(prose);
      if (rekeyNonce) this.sendLive = await this.deriveNext(live, rekeyNonce);
      else this.kickRekey();
    });
  }
  kickRekey() {
    if (this.rekeyBusy || this.closed || !this.initiator || this.sendLive !== this.recvLive) return;
    const dir = this.initiator ? "e2g" : "g2e";
    const peer = this.recvLive.seen[dir === "e2g" ? "g2e" : "e2g"];
    const stale = currentWindow() !== this.sendLive.window;
    if (Math.max(this.sendLive.counters[dir], peer) < this.rekeyAt && !stale) return;
    this.rekeyBusy = true;
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const payload = concat(nonce, u32be(currentWindow()));
    void this.sendRecord(RECORD.rekey, 0, 0, payload, payload).finally(() => {
      if (this.sendLive === this.recvLive) this.rekeyBusy = false;
    });
  }
  async deriveNext(base, payload) {
    if (payload.length < 20) throw new Error("\u6362\u94A5\u62A5\u6587\u592A\u77ED");
    const nonce = payload.subarray(0, 16);
    const window = readU32(payload, 16);
    const sk = await hkdf(base.sk, nonce, utf8("lexis-rekey-v1"), 32);
    const lexicon = await sessionLexicon(sk, window);
    return {
      ...base,
      sk,
      window,
      lexicon,
      inverse: invertLexicon(lexicon),
      counters: { e2g: 0, g2e: 0 },
      seen: { e2g: 0, g2e: 0 }
    };
  }
  async openLive(live, prose, honey = live.honey) {
    const dir = this.initiator ? "g2e" : "e2g";
    const opened = await open({
      key: live.sk,
      inverse: live.inverse,
      window: live.window,
      direction: dir,
      prose,
      lastSeen: live.seen[dir],
      honey,
      program: live.program ?? null
    });
    if (!opened.honey) live.seen[dir] = opened.counter;
    return opened;
  }
  async sendChunks(stream, chunk) {
    await stream.write(chunk);
  }
  async open(command) {
    if (this.streams.size >= this.maxStreams) throw new Error("\u8FD9\u6761\u94FE\u8DEF\u7684\u8FDE\u63A5\u6570\u5DF2\u6EE1");
    const id = this.nextId;
    this.nextId += 2;
    const stream = new MuxStream(this, id, true);
    stream.command = command;
    this.streams.set(id, stream);
    await this.sendRecord(RECORD.open, id, stream.seq, utf8(command));
    const ack = await Promise.race([
      stream.waitAck(),
      new Promise((resolve) => setTimeout(() => resolve({ ok: false, reason: "\u6253\u5F00\u8D85\u65F6" }), 15e3))
    ]);
    if (!ack.ok) {
      stream.finish();
      throw new Error(ack.reason || "\u5BF9\u7AEF\u62D2\u7EDD");
    }
    return stream;
  }
  async onRecord(type, conn, payload) {
    if (type === RECORD.heartbeat) return;
    if (type === RECORD.credit) {
      const n = payload.length >= 2 ? readU16(payload, 0) : 1;
      this.streams.get(conn)?.grant(n);
      return;
    }
    if (type === RECORD.rekey) {
      if (this.initiator) return;
      const next = await this.deriveNext(this.recvLive, payload);
      this.recvLive = next;
      this.sendLive = next;
      this.live = next;
      return;
    }
    if (type === RECORD.close) {
      this.streams.get(conn)?.finish();
      return;
    }
    if (type === RECORD.open) {
      const text = fromUtf8(payload).replace(/\0/g, "");
      const existing = this.streams.get(conn);
      if (existing) {
        if (text === "ok") existing.resolveAck({ ok: true, reason: "" });
        else if (text.startsWith("no ")) existing.resolveAck({ ok: false, reason: text.slice(3) });
        else existing.resolveAck({ ok: false, reason: text || "\u6253\u5F00\u5931\u8D25" });
        return;
      }
      if (this.streams.size >= this.maxStreams) return;
      const stream = new MuxStream(this, conn, false);
      stream.command = text;
      this.streams.set(conn, stream);
      this.onStream?.(stream);
      return;
    }
    if (type === RECORD.data) {
      const stream = this.streams.get(conn);
      if (!stream || stream.ended) return;
      if (stream.queued() > 32) {
        void stream.close();
        return;
      }
      stream.push(payload);
    }
  }
  async readLoop() {
    try {
      for (; ; ) {
        const prose = await this.pipe.read();
        const pending = this.sendLive !== this.recvLive;
        let opened;
        try {
          opened = await this.openLive(this.recvLive, prose, pending ? false : this.recvLive.honey);
        } catch (err2) {
          if (!pending) throw err2;
          try {
            opened = await this.openLive(this.sendLive, prose, false);
            this.recvLive = this.sendLive;
            this.live = this.sendLive;
            this.rekeyBusy = false;
          } catch (err22) {
            if (this.sendLive.honey || this.recvLive.honey) continue;
            throw err22;
          }
        }
        if (opened.honey) continue;
        this.lastRx = Date.now();
        let rec;
        try {
          const raw = await unpackRecord(opened.plaintext);
          rec = decodeRecord(raw);
        } catch {
          continue;
        }
        await this.onRecord(rec.type, rec.conn, rec.payload);
      }
    } catch (err2) {
      const message = err2 instanceof Error ? err2.message : String(err2);
      if (!this.closed && message !== "\u8FDE\u63A5\u5173\u95ED") console.error("\u8BCD\u9699\u4F1A\u8BDD\u7ED3\u675F", message);
      this.shutdown();
    }
  }
};
async function sessionFrom(pipe, live, initiator, zstd, maxStreams, heartbeatMs, onStream, rekeyAt = 16776960, peerId = "", onReady) {
  pipe.setCap?.(FRAME_CAP);
  const session = new LexSession(pipe, live, initiator, zstd, maxStreams, heartbeatMs, rekeyAt);
  session.peerId = peerId;
  if (onStream) session.onStream = onStream;
  onReady?.(session);
  void session.readLoop();
  return session;
}
async function connectSession(opts) {
  const self = { ...opts.self, role: "edge" };
  const token = opts.token || "";
  const wait = opts.handshakeMs ?? 1e4;
  const pending = await edgeStart(self, Date.now(), opts.offer, token);
  await opts.pipe.write(pending.helloWire);
  const serverWire = await opts.pipe.read(wait);
  const finished = await edgeFinish(self, pending, opts.peerRawB64, serverWire, token);
  await opts.pipe.write(finished.finishWire);
  const live = await openSession({
    edge: self,
    gate: { ...self, id: "peer", name: "\u5BF9\u7AEF", role: "gate", publicRawB64: opts.peerRawB64 },
    sk: finished.sk,
    window: finished.window,
    helloWire: pending.helloWire,
    serverWire,
    finishWire: finished.finishWire,
    kdf: finished.kdf,
    honey: finished.honey,
    kdfMs: finished.kdfMs,
    program: opts.program ?? null
  });
  return sessionFrom(
    opts.pipe,
    live,
    true,
    opts.zstd || { enabled: false, level: 3 },
    opts.maxStreams || 128,
    opts.heartbeatMs ?? 15e3,
    opts.onStream,
    opts.rekeyAt,
    opts.peerId || "",
    opts.onReady
  );
}
async function acceptSession(opts) {
  const self = { ...opts.self, role: "gate" };
  const wait = opts.handshakeMs ?? 1e4;
  const helloWire = await opts.pipe.read(wait);
  let pending = null;
  let matched = "";
  let last = "\u6CA1\u6709\u5339\u914D\u7684\u8282\u70B9\u516C\u94A5";
  for (const peer of opts.peers) {
    if (!peer.publicRawB64) continue;
    try {
      pending = await gateRespond(self, peer.publicRawB64, helloWire, {
        token: opts.token,
        kdf: opts.kdf,
        sourceIp: opts.sourceIp,
        peerId: peer.id || ""
      });
      matched = peer.id || "";
      break;
    } catch (err2) {
      const message = err2 instanceof Error ? err2.message : String(err2);
      last = message;
      if (!message.includes("\u7ED1\u5B9A\u4E0D\u4E00\u81F4")) throw err2;
    }
  }
  if (!pending) throw new Error(last);
  await opts.pipe.write(pending.serverWire);
  const finishWire = await opts.pipe.read(wait);
  await gateAccept(pending, finishWire);
  const honey = honeyFromFeatures(pending.features);
  const live = await openSession({
    edge: { ...self, id: matched || "peer", name: "\u5BF9\u7AEF", role: "edge", publicRawB64: b64(pending.ltC) },
    gate: self,
    sk: pending.sk,
    window: pending.window,
    helloWire,
    serverWire: pending.serverWire,
    finishWire,
    kdf: pending.kdf,
    honey,
    kdfMs: 0,
    program: opts.program ?? null
  });
  return sessionFrom(
    opts.pipe,
    live,
    false,
    opts.zstd || { enabled: false, level: 3 },
    opts.maxStreams || 128,
    opts.heartbeatMs ?? 15e3,
    opts.onStream,
    opts.rekeyAt,
    matched,
    opts.onReady
  );
}
async function pipeMux(left, right) {
  const pump = async (src, dst) => {
    try {
      for (; ; ) {
        const chunk = await src.read();
        if (!chunk) {
          await dst.close();
          return;
        }
        await dst.write(chunk);
      }
    } catch {
      await dst.close().catch(() => void 0);
      await src.close().catch(() => void 0);
    }
  };
  void pump(left, right);
  void pump(right, left);
}
if (!isMainThread && parentPort) {
  parentPort.on("message", (msg) => {
    if (msg.crash) throw new Error("\u6D3E\u751F\u7EBF\u7A0B\u6545\u969C");
    try {
      const out = deriveSessionKey(msg.ssE, msg.ssS, msg.nonceC, msg.nonceS, msg.window, msg.features, msg.params);
      parentPort?.postMessage({ id: msg.id, key: out.key, ms: out.ms });
    } catch (err2) {
      parentPort?.postMessage({ id: msg.id, error: err2 instanceof Error ? err2.message : String(err2) });
    }
  });
}
var kdfWorker = null;
var kdfSeq = 0;
var kdfInflight = 0;
var kdfMax = 2;
var kdfWait = /* @__PURE__ */ new Map();
var KDF_TASK_MS = 6e4;
function failKdfWaiters(err2) {
  const jobs = [...kdfWait.values()];
  kdfWait.clear();
  for (const job of jobs) job.reject(err2);
}
function dropKdfWorker(err2) {
  const worker = kdfWorker;
  kdfWorker = null;
  failKdfWaiters(err2);
  if (!worker) return;
  void worker.terminate().catch(() => void 0);
}
function ensureKdfWorker() {
  if (!isMainThread || kdfWorker) return;
  const worker = new Worker(new URL(import.meta.url));
  kdfWorker = worker;
  worker.unref?.();
  worker.on("message", (msg) => {
    const job = kdfWait.get(msg.id);
    if (!job) return;
    kdfWait.delete(msg.id);
    if (msg.error || !msg.key) job.reject(new Error(msg.error || "\u6D3E\u751F\u5931\u8D25"));
    else job.resolve({ key: new Uint8Array(msg.key), ms: msg.ms || 1 });
  });
  worker.on("error", (err2) => {
    if (kdfWorker !== worker) return;
    dropKdfWorker(err2 instanceof Error ? err2 : new Error(String(err2)));
  });
  worker.on("exit", () => {
    if (kdfWorker !== worker) return;
    kdfWorker = null;
    failKdfWaiters(new Error("\u6D3E\u751F\u7EBF\u7A0B\u5DF2\u505C"));
  });
}
function breakKdfWorkerForTests() {
  const worker = kdfWorker;
  if (!worker) return Promise.resolve();
  return new Promise((resolve) => {
    worker.once("exit", () => resolve());
    worker.postMessage({ crash: true });
  });
}
function startKdfPool(maxConcurrent = 2) {
  kdfMax = Math.max(1, Math.min(8, maxConcurrent || 2));
  ensureKdfWorker();
  setSessionKeyDeriver(async (ssE, ssS, nonceC, nonceS, window, features, params) => {
    ensureKdfWorker();
    const worker = kdfWorker;
    if (!worker) return deriveSessionKey(ssE, ssS, nonceC, nonceS, window, features, params);
    if (kdfInflight >= kdfMax) throw new Error("\u63E1\u624B\u592A\u591A");
    kdfInflight += 1;
    const id = ++kdfSeq;
    try {
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          if (!kdfWait.has(id)) return;
          kdfWait.delete(id);
          reject(new Error("\u6D3E\u751F\u8D85\u65F6"));
          if (kdfWorker === worker) dropKdfWorker(new Error("\u6D3E\u751F\u8D85\u65F6"));
        }, KDF_TASK_MS);
        timer.unref?.();
        kdfWait.set(id, {
          resolve: (value) => {
            clearTimeout(timer);
            resolve(value);
          },
          reject: (err2) => {
            clearTimeout(timer);
            reject(err2);
          }
        });
        try {
          worker.postMessage({ id, ssE, ssS, nonceC, nonceS, window, features, params });
        } catch (err2) {
          kdfWait.delete(id);
          clearTimeout(timer);
          reject(err2 instanceof Error ? err2 : new Error(String(err2)));
          if (kdfWorker === worker) dropKdfWorker(err2 instanceof Error ? err2 : new Error(String(err2)));
        }
      });
    } finally {
      kdfInflight = Math.max(0, kdfInflight - 1);
    }
  });
}
export {
  LexSession,
  MuxStream,
  acceptSession,
  breakKdfWorkerForTests,
  connectSession,
  createIdentity,
  dialOuter,
  hopCount,
  listenOuter,
  nodeFromIdentity,
  openIdentityVault,
  parseOpen,
  pipeMux,
  programFromStored,
  startKdfPool,
  tcpPipe,
  vaultFromStored,
  wsClientPipe,
  wsServerPipe
};
/*! Bundled license information:

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/weierstrass.js:
@noble/curves/nist.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
