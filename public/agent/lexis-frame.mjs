// src/agent/frame.ts
import { createHash, randomBytes as randomBytes2 } from "node:crypto";
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

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes(bytes));
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
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "output");
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
function clean(...arrays) {
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
    clean(encoded);
  }
}
function kdfInputToBytes(data, errorTitle = "") {
  if (typeof data === "string")
    return utf8ToBytes(data);
  return abytes(data, void 0, errorTitle);
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
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
  anumber(keyLen);
  if (outputLen <= 0 || outputLen > keyLen)
    throw new Error('"dkLen" must be 1..' + keyLen + ", got " + outputLen);
  const { key: key2, salt, personalization } = opts;
  if (key2 !== void 0 && (key2.length < 1 || key2.length > keyLen))
    throw new Error('"key" expected to be undefined or of length=1..' + keyLen);
  if (salt !== void 0)
    abytes(salt, saltLen, "salt");
  if (personalization !== void 0)
    abytes(personalization, persLen, "personalization");
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
    anumber(blockLen);
    anumber(outputLen);
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.buffer = new Uint8Array(blockLen);
    this.buffer32 = u32(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
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
    aexists(this);
    aoutput(out, this);
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
      abytes(key2, void 0, "key");
      keyLength = key2.length;
    }
    this.v0l ^= this.outputLen | keyLength << 8 | 1 << 16 | 1 << 24;
    if (salt !== void 0) {
      abytes(salt, void 0, "salt");
      const slt = u32(copyBytes(salt));
      this.v4l ^= swap8IfBE(slt[0]);
      this.v4h ^= swap8IfBE(slt[1]);
      this.v5l ^= swap8IfBE(slt[2]);
      this.v5h ^= swap8IfBE(slt[3]);
    }
    if (personalization !== void 0) {
      abytes(personalization, void 0, "personalization");
      const pers = u32(copyBytes(personalization));
      this.v6l ^= swap8IfBE(pers[0]);
      this.v6h ^= swap8IfBE(pers[1]);
      this.v7l ^= swap8IfBE(pers[2]);
      this.v7h ^= swap8IfBE(pers[3]);
    }
    if (key2 !== void 0) {
      const tmp = new Uint8Array(this.blockLen);
      tmp.set(key2);
      this.update(tmp);
      clean(tmp);
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
    clean(BBUF);
  }
  destroy() {
    this.destroyed = true;
    clean(this.buffer32);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var blake2b = /* @__PURE__ */ createHasher((opts) => new _BLAKE2b(opts));

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
  clean(A2_BUF);
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
  clean(V, T);
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
  anumber(asyncTick, "asyncTick");
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
    clean(BUF, ...ownedInputs);
    if (!succeeded && H0)
      clean(H0);
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
    clean(H0);
  }
}
function argon2Output(B, p, laneLen, dkLen) {
  const B_final = new Uint32Array(256);
  for (let l = 0; l < p; l++)
    for (let j = 0; j < 256; j++)
      B_final[j] ^= B[256 * (laneLen * l + laneLen - 1) + j];
  const res = Hp(swap32IfBE(B_final), dkLen);
  clean(B, B_final);
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
  clean(address);
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
  const confirmS = (await hmac(sk, concat(utf8("lexis-srv-v1"), tr))).subarray(0, 16);
  const expectFinish = (await hmac(sk, concat(utf8("lexis-cli-v1"), tr))).subarray(0, 16);
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
  const expectS = (await hmac(sk, concat(utf8("lexis-srv-v1"), tr))).subarray(0, 16);
  if (!timingSafeEqual(expectS, server.confirm)) {
    throw new LexisError("\u95F8\u95E8\u786E\u8BA4\u6807\u8BB0\u5BF9\u4E0D\u4E0A\uFF0C\u4F1A\u8BDD\u5BC6\u94A5\u6CA1\u6709\u5BF9\u9F50");
  }
  const confirmC = (await hmac(sk, concat(utf8("lexis-cli-v1"), tr))).subarray(0, 16);
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
  const tag = (await hmac(
    key2,
    concat(utf8(`lexis-mac-v1|${direction}|`), u32be(counter), plaintext)
  )).subarray(0, SPEC.macBytes);
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
function macBit(a, b) {
  const n = Math.max(a.length, b.length);
  let diff = a.length === b.length ? 0 : 1;
  for (let i = 0; i < n; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return Number(diff === 0);
}
async function open(input) {
  const { key: key2, inverse, window, direction, prose, lastSeen } = input;
  const honey = input.honey === true;
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
  const raw = chunksToBytes(chunks);
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
  const tag = raw.slice(2 + len, 2 + len + SPEC.macBytes);
  const expect = (await hmac(key2, concat(utf8(`lexis-mac-v1|${direction}|`), u32be(counter), plaintext))).subarray(0, SPEC.macBytes);
  const ok = macBit(tag, expect);
  if (ok === 1) {
    if (counter < 1) throw new LexisError("\u8BA1\u6570\u5668\u65E0\u6548");
    if (counter <= lastSeen) throw new LexisError("\u8BA1\u6570\u5668\u6CA1\u6709\u524D\u8FDB\uFF0C\u6309\u56DE\u653E\u4E22\u5F03");
  } else if (!honey) {
    throw new LexisError("\u6821\u9A8C\u5931\u8D25\u3002\u5BC6\u94A5\u3001\u8BA1\u6570\u5668\u6216\u8BCD\u8868\u5BF9\u4E0D\u4E0A\u3002");
  }
  return release(ok, plaintext);
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
    const key2 = randomBytes2(4);
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
  const key2 = randomBytes2(16).toString("base64");
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
    const socket = tls ? connectTls({
      host: opts.host,
      port: opts.port,
      ...name ? { servername: name } : {},
      rejectUnauthorized: opts.tlsVerify !== false
    }) : connectTcp({ host: opts.host, port: opts.port });
    const fail = (err2) => {
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
        const raw = await unpackRecord(opened.plaintext);
        const rec = decodeRecord(raw);
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
  parseOpen,
  pipeMux,
  programFromStored,
  startKdfPool,
  tcpPipe,
  wsClientPipe,
  wsServerPipe
};
