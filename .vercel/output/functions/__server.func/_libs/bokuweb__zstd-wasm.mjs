import { r as __require, t as __commonJSMin } from "../_runtime.mjs";
//#region node_modules/@bokuweb/zstd-wasm/dist/common/zstd.js
var require_zstd = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.Module = void 0;
	var Module = typeof Module !== "undefined" ? Module : {};
	exports.Module = Module;
	var moduleOverrides = {};
	var key;
	for (key in Module) if (Module.hasOwnProperty(key)) moduleOverrides[key] = Module[key];
	var err = Module["printErr"] || console.warn.bind(console);
	for (key in moduleOverrides) if (moduleOverrides.hasOwnProperty(key)) Module[key] = moduleOverrides[key];
	var quit_ = (status, toThrow) => {
		throw toThrow;
	};
	moduleOverrides = null;
	if (Module["arguments"]) Module["arguments"];
	if (Module["thisProgram"]) thisProgram = Module["thisProgram"];
	if (Module["quit"]) quit_ = Module["quit"];
	if (typeof WebAssembly !== "object") abort("no native wasm support detected");
	var wasmMemory;
	var ABORT = false;
	var EXITSTATUS;
	var HEAPU8;
	function updateMemoryViews() {
		var b = wasmMemory.buffer;
		Module["HEAP8"] = new Int8Array(b);
		Module["HEAPU8"] = HEAPU8 = new Uint8Array(b);
	}
	var __ATPRERUN__ = [];
	var __ATINIT__ = [];
	var __ATPOSTRUN__ = [];
	function preRun() {
		if (Module["preRun"]) {
			if (typeof Module["preRun"] == "function") Module["preRun"] = [Module["preRun"]];
			while (Module["preRun"].length) addOnPreRun(Module["preRun"].shift());
		}
		callRuntimeCallbacks(__ATPRERUN__);
	}
	function initRuntime() {
		callRuntimeCallbacks(__ATINIT__);
	}
	function postRun() {
		if (Module["postRun"]) {
			if (typeof Module["postRun"] == "function") Module["postRun"] = [Module["postRun"]];
			while (Module["postRun"].length) addOnPostRun(Module["postRun"].shift());
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
		(_a = Module["monitorRunDependencies"]) === null || _a === void 0 || _a.call(Module, runDependencies);
	}
	function removeRunDependency(id) {
		var _a;
		runDependencies--;
		(_a = Module["monitorRunDependencies"]) === null || _a === void 0 || _a.call(Module, runDependencies);
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
		(_a = Module["onAbort"]) === null || _a === void 0 || _a.call(Module, what);
		what = "Aborted(" + what + ")";
		err(what);
		ABORT = true;
		what += ". Build with -sASSERTIONS for more info.";
		throw new WebAssembly.RuntimeError(what);
	}
	function getWasmImports() {
		return { a: wasmImports };
	}
	function getBinaryPromise(url) {
		return fetch(url, { credentials: "same-origin" }).then(function(response) {
			if (!response["ok"]) throw "failed to load wasm binary file at '" + url + "'";
			return response["arrayBuffer"]();
		});
	}
	function init(filePathOrBuf) {
		var info = getWasmImports();
		function receiveInstance(instance, module$1) {
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
				return WebAssembly.instantiate(binary, info);
			}).then(receiver, function(reason) {
				err("failed to asynchronously prepare wasm: " + reason);
				abort(reason);
			});
		}
		function instantiateAsync() {
			if (filePathOrBuf && filePathOrBuf.byteLength > 0) return WebAssembly.instantiate(filePathOrBuf, info).then(receiveInstantiationResult, function(reason) {
				err("wasm compile failed: " + reason);
			});
			else if (typeof WebAssembly.instantiateStreaming === "function" && typeof filePathOrBuf === "string" && typeof fetch === "function") return fetch(filePathOrBuf, { credentials: "same-origin" }).then(function(response) {
				return WebAssembly.instantiateStreaming(response, info).then(receiveInstantiationResult, function(reason) {
					err("wasm streaming compile failed: " + reason);
					err("falling back to ArrayBuffer instantiation");
					return instantiateArrayBuffer(receiveInstantiationResult);
				});
			});
			else return instantiateArrayBuffer(receiveInstantiationResult);
		}
		if (Module["instantiateWasm"]) try {
			return Module["instantiateWasm"](info, receiveInstance);
		} catch (e) {
			err("Module.instantiateWasm callback failed with error: " + e);
			return false;
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
		while (callbacks.length > 0) callbacks.shift()(Module);
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
		if (e instanceof ExitStatus || e == "unwind") return EXITSTATUS;
		quit_(1, e);
	};
	var keepRuntimeAlive = () => noExitRuntime || runtimeKeepaliveCounter > 0;
	var _proc_exit = (code) => {
		var _a;
		EXITSTATUS = code;
		if (!keepRuntimeAlive()) {
			(_a = Module["onExit"]) === null || _a === void 0 || _a.call(Module, code);
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
		if (!keepRuntimeAlive()) try {
			_exit(EXITSTATUS);
		} catch (e) {
			handleException(e);
		}
	};
	var callUserCallback = (func) => {
		if (ABORT) return;
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
		if (!timeout_ms) return 0;
		timers[which] = {
			id: setTimeout(() => {
				delete timers[which];
				callUserCallback(() => __emscripten_timeout(which, _emscripten_get_now()));
			}, timeout_ms),
			timeout_ms
		};
		return 0;
	};
	var getHeapMax = () => 2147483648;
	var alignMemory = (size, alignment) => Math.ceil(size / alignment) * alignment;
	var growMemory = (size) => {
		var pages = (size - wasmMemory.buffer.byteLength + 65535) / 65536 | 0;
		try {
			wasmMemory.grow(pages);
			updateMemoryViews();
			return 1;
		} catch (e) {}
	};
	var _emscripten_resize_heap = (requestedSize) => {
		var oldSize = HEAPU8.length;
		requestedSize >>>= 0;
		var maxHeapSize = getHeapMax();
		if (requestedSize > maxHeapSize) return false;
		for (var cutDown = 1; cutDown <= 4; cutDown *= 2) {
			var overGrownHeapSize = oldSize * (1 + .2 / cutDown);
			overGrownHeapSize = Math.min(overGrownHeapSize, requestedSize + 100663296);
			if (growMemory(Math.min(maxHeapSize, alignMemory(Math.max(requestedSize, overGrownHeapSize), 65536)))) return true;
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
		if (!calledRun) run();
		if (!calledRun) dependenciesFulfilled = runCaller;
	};
	function run() {
		if (runDependencies > 0) return;
		preRun();
		if (runDependencies > 0) return;
		function doRun() {
			var _a;
			if (calledRun) return;
			calledRun = true;
			Module["calledRun"] = true;
			if (ABORT) return;
			initRuntime();
			(_a = Module["onRuntimeInitialized"]) === null || _a === void 0 || _a.call(Module);
			postRun();
		}
		if (Module["setStatus"]) {
			Module["setStatus"]("Running...");
			setTimeout(() => {
				setTimeout(() => Module["setStatus"](""), 1);
				doRun();
			}, 1);
		} else doRun();
	}
	Module["run"] = run;
	if (Module["preInit"]) {
		if (typeof Module["preInit"] == "function") Module["preInit"] = [Module["preInit"]];
		while (Module["preInit"].length > 0) Module["preInit"].pop()();
	}
	Module["init"] = init;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/module.js
var require_module = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
		function adopt(value) {
			return value instanceof P ? value : new P(function(resolve) {
				resolve(value);
			});
		}
		return new (P || (P = Promise))(function(resolve, reject) {
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
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.Module = exports.waitInitialized = void 0;
	var zstd_1 = require_zstd();
	Object.defineProperty(exports, "Module", {
		enumerable: true,
		get: function() {
			return zstd_1.Module;
		}
	});
	var initialized = (() => new Promise((resolve) => {
		zstd_1.Module.onRuntimeInitialized = resolve;
	}))();
	var waitInitialized = () => __awaiter(void 0, void 0, void 0, function* () {
		yield initialized;
	});
	exports.waitInitialized = waitInitialized;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/errors/index.js
var require_errors = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.isError = void 0;
	var module_1 = require_module();
	var isError = (code) => {
		const _isError = module_1.Module["_ZSTD_isError"];
		return _isError(code);
	};
	exports.isError = isError;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/simple/decompress.js
var require_decompress = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.decompress = void 0;
	var module_1 = require_module();
	var errors_1 = require_errors();
	var getFrameContentSize = (src, size) => {
		const getSize = module_1.Module["_ZSTD_getFrameContentSize"];
		return getSize(src, size);
	};
	var decompress = (buf, opts = { defaultHeapSize: 1048576 }) => {
		const malloc = module_1.Module["_malloc"];
		const src = malloc(buf.byteLength);
		module_1.Module.HEAP8.set(buf, src);
		const contentSize = getFrameContentSize(src, buf.byteLength);
		const size = contentSize === -1 ? opts.defaultHeapSize : contentSize;
		const free = module_1.Module["_free"];
		const heap = malloc(size);
		try {
			const _decompress = module_1.Module["_ZSTD_decompress"];
			const sizeOrError = _decompress(heap, size, src, buf.byteLength);
			if ((0, errors_1.isError)(sizeOrError)) throw new Error(`Failed to compress with code ${sizeOrError}`);
			const data = new Uint8Array(module_1.Module.HEAPU8.buffer, heap, sizeOrError).slice();
			free(heap, size);
			free(src, buf.byteLength);
			return data;
		} catch (e) {
			free(heap, size);
			free(src, buf.byteLength);
			throw e;
		}
	};
	exports.decompress = decompress;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/simple/compress.js
var require_compress = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.compress = void 0;
	var module_1 = require_module();
	var errors_1 = require_errors();
	var compressBound = (size) => {
		const bound = module_1.Module["_ZSTD_compressBound"];
		return bound(size);
	};
	var compress = (buf, level) => {
		const bound = compressBound(buf.byteLength);
		const malloc = module_1.Module["_malloc"];
		const compressed = malloc(bound);
		const src = malloc(buf.byteLength);
		module_1.Module.HEAP8.set(buf, src);
		const free = module_1.Module["_free"];
		try {
			const _compress = module_1.Module["_ZSTD_compress"];
			const sizeOrError = _compress(compressed, bound, src, buf.byteLength, level !== null && level !== void 0 ? level : 3);
			if ((0, errors_1.isError)(sizeOrError)) throw new Error(`Failed to compress with code ${sizeOrError}`);
			const data = new Uint8Array(module_1.Module.HEAPU8.buffer, compressed, sizeOrError).slice();
			free(compressed, bound);
			free(src, buf.byteLength);
			return data;
		} catch (e) {
			free(compressed, bound);
			free(src, buf.byteLength);
			throw e;
		}
	};
	exports.compress = compress;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/simple/decompress_using_dict.js
var require_decompress_using_dict = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.decompressUsingDict = exports.freeDCtx = exports.createDCtx = void 0;
	var module_1 = require_module();
	var errors_1 = require_errors();
	var getFrameContentSize = (src, size) => {
		const getSize = module_1.Module["_ZSTD_getFrameContentSize"];
		return getSize(src, size);
	};
	var createDCtx = () => {
		return module_1.Module["_ZSTD_createDCtx"]();
	};
	exports.createDCtx = createDCtx;
	var freeDCtx = (dctx) => {
		return module_1.Module["_ZSTD_freeDCtx"](dctx);
	};
	exports.freeDCtx = freeDCtx;
	var decompressUsingDict = (dctx, buf, dict, opts = { defaultHeapSize: 1048576 }) => {
		const malloc = module_1.Module["_malloc"];
		const src = malloc(buf.byteLength);
		module_1.Module.HEAP8.set(buf, src);
		const pdict = malloc(dict.byteLength);
		module_1.Module.HEAP8.set(dict, pdict);
		const contentSize = getFrameContentSize(src, buf.byteLength);
		const size = contentSize === -1 ? opts.defaultHeapSize : contentSize;
		const free = module_1.Module["_free"];
		const heap = malloc(size);
		try {
			const _decompress = module_1.Module["_ZSTD_decompress_usingDict"];
			const sizeOrError = _decompress(dctx, heap, size, src, buf.byteLength, pdict, dict.byteLength);
			if ((0, errors_1.isError)(sizeOrError)) throw new Error(`Failed to compress with code ${sizeOrError}`);
			const data = new Uint8Array(module_1.Module.HEAPU8.buffer, heap, sizeOrError).slice();
			free(heap, size);
			free(src, buf.byteLength);
			free(pdict, dict.byteLength);
			return data;
		} catch (e) {
			free(heap, size);
			free(src, buf.byteLength);
			free(pdict, dict.byteLength);
			throw e;
		}
	};
	exports.decompressUsingDict = decompressUsingDict;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/simple/compress_using_dict.js
var require_compress_using_dict = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.compressUsingDict = exports.freeCCtx = exports.createCCtx = void 0;
	var module_1 = require_module();
	var errors_1 = require_errors();
	var compressBound = (size) => {
		const bound = module_1.Module["_ZSTD_compressBound"];
		return bound(size);
	};
	var createCCtx = () => {
		return module_1.Module["_ZSTD_createCCtx"]();
	};
	exports.createCCtx = createCCtx;
	var freeCCtx = (cctx) => {
		return module_1.Module["_ZSTD_freeCCtx"](cctx);
	};
	exports.freeCCtx = freeCCtx;
	var compressUsingDict = (cctx, buf, dict, level) => {
		const bound = compressBound(buf.byteLength);
		const malloc = module_1.Module["_malloc"];
		const compressed = malloc(bound);
		const src = malloc(buf.byteLength);
		module_1.Module.HEAP8.set(buf, src);
		const pdict = malloc(dict.byteLength);
		module_1.Module.HEAP8.set(dict, pdict);
		const free = module_1.Module["_free"];
		try {
			const _compress = module_1.Module["_ZSTD_compress_usingDict"];
			const sizeOrError = _compress(cctx, compressed, bound, src, buf.byteLength, pdict, dict.byteLength, level !== null && level !== void 0 ? level : 3);
			if ((0, errors_1.isError)(sizeOrError)) throw new Error(`Failed to compress with code ${sizeOrError}`);
			const data = new Uint8Array(module_1.Module.HEAPU8.buffer, compressed, sizeOrError).slice();
			free(compressed, bound);
			free(src, buf.byteLength);
			free(pdict, dict.byteLength);
			return data;
		} catch (e) {
			free(compressed, bound);
			free(src, buf.byteLength);
			free(pdict, dict.byteLength);
			throw e;
		}
	};
	exports.compressUsingDict = compressUsingDict;
}));
//#endregion
//#region node_modules/@bokuweb/zstd-wasm/dist/common/index.node.js
var require_index_node = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		var desc = Object.getOwnPropertyDescriptor(m, k);
		if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) desc = {
			enumerable: true,
			get: function() {
				return m[k];
			}
		};
		Object.defineProperty(o, k2, desc);
	}) : (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		o[k2] = m[k];
	}));
	var __exportStar = exports && exports.__exportStar || function(m, exports$1) {
		for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports$1, p)) __createBinding(exports$1, m, p);
	};
	var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
		function adopt(value) {
			return value instanceof P ? value : new P(function(resolve) {
				resolve(value);
			});
		}
		return new (P || (P = Promise))(function(resolve, reject) {
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
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.init = void 0;
	var module_1 = require_module();
	var init = () => __awaiter(void 0, void 0, void 0, function* () {
		const { readFile } = __require("fs/promises");
		const { resolve } = __require("path");
		const buf = yield readFile(resolve(__dirname, "./zstd.wasm"));
		module_1.Module["init"](buf);
		yield (0, module_1.waitInitialized)();
	});
	exports.init = init;
	__exportStar(require_decompress(), exports);
	__exportStar(require_compress(), exports);
	__exportStar(require_decompress_using_dict(), exports);
	__exportStar(require_compress_using_dict(), exports);
}));
//#endregion
export { require_index_node as t };
