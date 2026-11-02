//#region node_modules/@noble/ciphers/utils.js
/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */
/**
* Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
* @param a - Value to inspect.
* @returns `true` when the value is a Uint8Array view, including Node's `Buffer`.
* @example
* Guards a value before treating it as raw key material.
*
* ```ts
* isBytes(new Uint8Array());
* ```
*/
function isBytes(a) {
	return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
/**
* Asserts something is a non-negative safe integer.
* @param n - Value to validate.
* @returns The validated number.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validates a non-negative length or counter.
*
* ```ts
* anumber(1);
* ```
*/
function anumber(n, title = "") {
	if (typeof n !== "number") throw new TypeError(atitle(title) + "expected number, got " + typeof n);
	if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
	return n;
}
/**
* Asserts something is Uint8Array.
* @param value - Value to validate.
* @param length - Expected byte length.
* @param title - Optional label used in error messages.
* @returns The validated byte array.
* On Node, `Buffer` is accepted too because it is a Uint8Array view.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument lengths. {@link RangeError}
* @example
* Validates a fixed-length nonce or key buffer.
*
* ```ts
* abytes(new Uint8Array([1, 2]), 2);
* ```
*/
function abytes(value, length, title = "") {
	if (isBytes(value) && (length === void 0 || value.length === length)) return value;
	if (length !== void 0) anumber(length, "length");
	const bytes = isBytes(value);
	const ofLen = length !== void 0 ? ` of length ${length}` : "";
	const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
	const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
	if (!bytes) throw new TypeError(message);
	throw new RangeError(message);
}
/**
* Asserts a hash- or MAC-like instance has not been destroyed or finished.
* @param instance - Stateful instance to validate.
* @param checkFinished - Whether to reject finished instances.
* When `false`, only `destroyed` is checked.
* @throws If the hash instance has already been destroyed or finalized. {@link Error}
* @example
* Guards against calling `update()` or `digest()` on a finished hash.
*
* ```ts
* aexists({ destroyed: false, finished: false });
* ```
*/
function aexists(instance, checkFinished = true) {
	if (instance.destroyed) throw new Error("hash was destroyed");
	if (checkFinished && instance.finished) throw new Error("digest() was already called");
}
/**
* Asserts output is a sufficiently-sized byte array.
* @param out - Output buffer to validate.
* @param instance - Hash-like instance providing `outputLen`.
* This is the relaxed `digestInto()`-style contract: output must be at least `outputLen`,
* unlike one-shot cipher helpers elsewhere in the repo that often require exact lengths.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong output buffer lengths. {@link RangeError}
* @example
* Verifies that a caller-provided output buffer is large enough.
*
* ```ts
* aoutput(new Uint8Array(16), { outputLen: 16 });
* ```
*/
function aoutput(out, instance) {
	abytes(out, void 0, "output");
	const min = instance.outputLen;
	if (!(out.length >= min)) throw new RangeError("\"output\" expected length >= " + min);
}
/**
* Asserts output is a sufficiently-sized, 4-byte-aligned byte array.
* {@link aoutput} plus an {@link isAligned32} check, for `digestInto()` paths
* that write through zero-allocation `u32` word views.
* @param out - Output buffer to validate.
* @param instance - Hash-like instance providing `outputLen`.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong output buffer lengths. {@link RangeError}
* @throws On wrong output buffer alignment. {@link Error}
* @example
* Verifies that a caller-provided output buffer is large enough and aligned.
*
* ```ts
* aoutput32(new Uint8Array(16), { outputLen: 16 });
* ```
*/
function aoutput32(out, instance) {
	aoutput(out, instance);
	if (!isAligned32(out)) throw new Error("invalid output, must be aligned");
}
/**
* Casts a typed-array view to Uint8Array.
* @param arr - Typed-array view to reinterpret.
* @returns Uint8Array view over the same bytes.
* @example
* Views 32-bit words as raw bytes without copying.
*
* ```ts
* u8(new Uint32Array([1]));
* ```
*/
function u8(arr) {
	return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
/**
* Casts a typed-array view to Uint32Array.
* @param arr - Typed-array view to reinterpret.
* @returns Uint32Array view over the same bytes. Callers are expected to provide a
* 4-byte-aligned offset; trailing `1..3` bytes are silently dropped.
* @example
* Views a byte buffer as 32-bit words for block processing.
*
* ```ts
* u32(new Uint8Array(4));
* ```
*/
function u32(arr) {
	return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/**
* Zeroizes typed arrays in place.
* Warning: JS provides no guarantees.
* @param arrays - Arrays to wipe.
* @example
* Wipes a temporary key buffer after use.
*
* ```ts
* const bytes = new Uint8Array([1]);
* clean(bytes);
* ```
*/
function clean(...arrays) {
	for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
}
/**
* Creates a DataView for byte-level manipulation.
* @param arr - Typed-array view to wrap.
* @returns DataView over the same bytes.
* @example
* Creates an endian-aware view for length encoding.
*
* ```ts
* createView(new Uint8Array(4));
* ```
*/
function createView(arr) {
	return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/**
* Whether the current platform is little-endian.
* Most are; some IBM systems are not.
*/
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
/**
* Reverses byte order of one 32-bit word.
* @param word - Unsigned 32-bit word to swap.
* @returns The same word with bytes reversed.
* @example
* Swaps a big-endian word into little-endian byte order.
*
* ```ts
* byteSwap(0x11223344);
* ```
*/
function byteSwap(word) {
	return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
/**
* Normalizes one 32-bit word to the little-endian representation expected by cipher cores.
* @param n - Unsigned 32-bit word to normalize.
* @returns Little-endian normalized word on big-endian hosts, else the input word unchanged.
* @example
* Normalizes a host-endian word before passing it into an ARX/AES core.
*
* ```ts
* swap8IfBE(0x11223344);
* ```
*/
var swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n) >>> 0;
/**
* Byte-swaps every word of a Uint32Array in place.
* @param arr - Uint32Array whose words should be swapped.
* @returns The same array after in-place byte swapping.
* @example
* Swaps every 32-bit word in a word-view buffer.
*
* ```ts
* byteSwap32(new Uint32Array([0x11223344]));
* ```
*/
function byteSwap32(arr) {
	for (let i = 0; i < arr.length; i++) arr[i] = byteSwap(arr[i]);
	return arr;
}
/**
* Normalizes a Uint32Array view to the little-endian representation expected by cipher cores.
* @param u - Word view to normalize in place.
* @returns Little-endian normalized word view.
* @example
* Normalizes a word-view buffer before block processing.
*
* ```ts
* swap32IfBE(new Uint32Array([0x11223344]));
* ```
*/
var swap32IfBE = isLE ? (u) => u : byteSwap32;
/**
* Checks if two U8A use same underlying buffer and overlaps.
* This is invalid and can corrupt data.
* @param a - First byte view.
* @param b - Second byte view.
* @returns `true` when the views overlap in memory.
* @example
* Detects whether two slices alias the same backing buffer.
*
* ```ts
* overlapBytes(new Uint8Array(4), new Uint8Array(4));
* ```
*/
function overlapBytes(a, b) {
	if (!a.byteLength || !b.byteLength) return false;
	return a.buffer === b.buffer && a.byteOffset < b.byteOffset + b.byteLength && b.byteOffset < a.byteOffset + a.byteLength;
}
/**
* If input and output overlap and input starts before output, we will overwrite end of input before
* we start processing it, so this is not supported by forward-processing ciphers.
* @param input - Input bytes.
* @param output - Output bytes.
* @throws If the output view would overwrite unread input bytes. {@link Error}
* @example
* Rejects an in-place layout that would overwrite unread input bytes.
*
* ```ts
* const buffer = new Uint8Array(8);
* complexOverlapBytes(buffer.subarray(0, 4), buffer.subarray(2, 6));
* ```
*/
function complexOverlapBytes(input, output) {
	if (overlapBytes(input, output) && input.byteOffset < output.byteOffset) throw new Error("complex overlap of input and output is not supported");
}
/**
* Wraps a keyed MAC constructor into a one-shot helper with `.create()`.
* @param keyLen - Valid probe-key length used to read static metadata once.
* The probe key is only used for `outputLen` / `blockLen`, so callers with several valid key sizes
* can pass any representative size as long as those values stay fixed.
* @param macCons - Keyed MAC constructor or factory.
* @param fromMsg - Optional adapter that derives extra constructor args from the one-shot message.
* @returns Callable MAC helper with `.create()`.
*/
function wrapMacConstructor(keyLen, macCons, fromMsg) {
	const mac = macCons;
	const getArgs = fromMsg || (() => []);
	const macC = (msg, key) => mac(key, ...getArgs(msg)).update(msg).digest();
	const tmp = mac(new Uint8Array(keyLen), ...getArgs(/* @__PURE__ */ new Uint8Array(0)));
	macC.outputLen = tmp.outputLen;
	macC.blockLen = tmp.blockLen;
	macC.create = (key, ...args) => mac(key, ...args);
	return macC;
}
/**
* Wraps a cipher: validates args, ensures encrypt() can only be called once.
* Used internally by the exported cipher constructors.
* Output-buffer support is inferred from the wrapped `encrypt` / `decrypt`
* arity (`fn.length === 2`), so wrapped output-capable methods must use a normal
* second parameter, not a default/rest parameter. AAD support is explicit in
* `params.withAAD`; optional AAD starts after the nonce slot when one is present.
* @__NO_SIDE_EFFECTS__
* @param params - Static cipher metadata. See {@link CipherParams}.
* @param constructor - Cipher constructor.
* @returns Wrapped constructor with validation.
*/
var wrapCipher = (params, constructor) => {
	function wrappedCipher(key, ...args) {
		abytes(key, void 0, "key");
		if (params.nonceLength !== void 0) {
			const nonce = args[0];
			abytes(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
		}
		const tagl = params.tagLength;
		const aadStart = params.nonceLength !== void 0 ? 1 : 0;
		if (!params.withAAD) {
			for (let i = aadStart; i < args.length; i++) if (isBytes(args[i])) throw new Error("AAD not supported");
		}
		if (params.withAAD && args[aadStart] !== void 0) abytes(args[aadStart], void 0, "AAD");
		const cipher = constructor(key, ...args);
		const checkOutput = (fnLength, output) => {
			if (output !== void 0) {
				if (fnLength !== 2) throw new Error("cipher output not supported");
				abytes(output, void 0, "output");
			}
		};
		let called = false;
		return {
			encrypt(data, output) {
				if (called) throw new Error("cannot encrypt() twice with same key + nonce");
				called = true;
				abytes(data, void 0, "data");
				checkOutput(cipher.encrypt.length, output);
				return cipher.encrypt(data, output);
			},
			decrypt(data, output) {
				abytes(data, void 0, "data");
				if (tagl && data.length < tagl) throw new Error("\"ciphertext\" expected length >= tagLength=" + tagl);
				checkOutput(cipher.decrypt.length, output);
				return cipher.decrypt(data, output);
			}
		};
	}
	Object.assign(wrappedCipher, params);
	return wrappedCipher;
};
/**
* By default, returns u8a of length.
* When out is available, it checks it for validity and uses it.
* @param expectedLength - Required output length.
* @param out - Optional destination buffer.
* @param onlyAligned - Whether `out` must be 4-byte aligned.
* @returns Output buffer ready for writing.
* @throws On wrong argument types. {@link TypeError}
* @throws If the provided output buffer has the wrong size. {@link RangeError}
* @throws If the provided output buffer has the wrong alignment. {@link Error}
* @example
* Reuses a caller-provided output buffer when lengths match.
*
* ```ts
* getOutput(16, new Uint8Array(16));
* ```
*/
function getOutput(expectedLength, out, onlyAligned = true) {
	if (out === void 0) return new Uint8Array(expectedLength);
	abytes(out, expectedLength, "output");
	if (onlyAligned && !isAligned32(out)) throw new Error("invalid output, must be aligned");
	return out;
}
/**
* Checks whether a byte array is aligned to a 4-byte offset.
* @param bytes - Byte array to inspect.
* @returns `true` when the view is 4-byte aligned.
* @example
* Checks whether a buffer can be safely viewed as Uint32Array.
*
* ```ts
* isAligned32(new Uint8Array(4));
* ```
*/
function isAligned32(bytes) {
	return bytes.byteOffset % 4 === 0;
}
/**
* Copies bytes into a new Uint8Array.
* @param bytes - Bytes to copy.
* @returns Copied byte array.
* @throws On wrong argument types. {@link TypeError}
* @example
* Copies input into an aligned Uint8Array before block processing.
*
* ```ts
* copyBytes(new Uint8Array([1, 2]));
* ```
*/
function copyBytes(bytes) {
	return Uint8Array.from(abytes(bytes));
}
//#endregion
//#region node_modules/@noble/ciphers/_polyval.js
/**
* GHash from AES-GCM and its little-endian "mirror image" Polyval from AES-SIV.
*
* Implemented in terms of GHash with conversion function for keys
* GCM GHASH from
* {@link https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf | NIST SP800-38d},
* SIV from
* {@link https://www.rfc-editor.org/rfc/rfc8452 | RFC 8452}.
*
* GHASH   modulo: x^128 + x^7   + x^2   + x     + 1
* POLYVAL modulo: x^128 + x^127 + x^126 + x^121 + 1
*
* @module
*/
var BLOCK_SIZE$1 = 16;
var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
var ZEROS32 = /* @__PURE__ */ u32(ZEROS16);
var POLY$1 = 225;
var mul2$1 = (s0, s1, s2, s3) => {
	const hiBit = s3 & 1;
	return {
		s3: s2 << 31 | s3 >>> 1,
		s2: s1 << 31 | s2 >>> 1,
		s1: s0 << 31 | s1 >>> 1,
		s0: s0 >>> 1 ^ POLY$1 << 24 & -(hiBit & 1)
	};
};
var swapLE = (n) => (n >>> 0 & 255) << 24 | (n >>> 8 & 255) << 16 | (n >>> 16 & 255) << 8 | n >>> 24 & 255 | 0;
var swap8IfLE = (n) => swap8IfBE(swapLE(n));
/**
* `mulX_GHASH(ByteReverse(H))` from RFC 8452 Appendix A.
* @param k mutated in place
*/
function _toGHASHKey(k) {
	k.reverse();
	const hiBit = k[15] & 1;
	let carry = 0;
	for (let i = 0; i < k.length; i++) {
		const t = k[i];
		k[i] = t >>> 1 | carry;
		carry = (t & 1) << 7;
	}
	k[0] ^= -hiBit & 225;
	return k;
}
var estimateWindow = (bytes) => {
	if (bytes > 65536) return 8;
	if (bytes > 1024) return 4;
	return 2;
};
/**
* Incremental GHASH state for AES-GCM.
* @param key - 16-byte GHASH key.
* @param expectedLength - Expected message length for table sizing.
* Chunking is segment-based, not hash-streaming: every `update()` call is zero-padded
* to the next 16-byte boundary before it is absorbed. This matches the internal AES/GCM
* use where AAD, payload, and length block are separate padded segments.
* @example
* Feeds one ciphertext block into an incremental GHASH state with a fresh hash key.
*
* ```ts
* import { GHASH } from '@noble/ciphers/_polyval.js';
* import { randomBytes } from '@noble/ciphers/utils.js';
* const key = randomBytes(16);
* const mac = new GHASH(key);
* mac.update(new Uint8Array(16));
* mac.digest();
* ```
*/
var GHASH = class {
	blockLen = BLOCK_SIZE$1;
	outputLen = BLOCK_SIZE$1;
	s0 = 0;
	s1 = 0;
	s2 = 0;
	s3 = 0;
	finished = false;
	destroyed = false;
	t;
	W;
	windowSize;
	constructor(key, expectedLength) {
		abytes(key, 16, "key");
		key = copyBytes(key);
		const kView = createView(key);
		let k0 = kView.getUint32(0, false);
		let k1 = kView.getUint32(4, false);
		let k2 = kView.getUint32(8, false);
		let k3 = kView.getUint32(12, false);
		const doubles = [];
		for (let i = 0; i < 128; i++) {
			doubles.push({
				s0: swapLE(k0),
				s1: swapLE(k1),
				s2: swapLE(k2),
				s3: swapLE(k3)
			});
			({s0: k0, s1: k1, s2: k2, s3: k3} = mul2$1(k0, k1, k2, k3));
		}
		const W = estimateWindow(expectedLength || 1024);
		if (![
			1,
			2,
			4,
			8
		].includes(W)) throw new Error("ghash: invalid window size, expected 2, 4 or 8");
		this.W = W;
		const windows = 128 / W;
		const windowSize = this.windowSize = 2 ** W;
		const items = [];
		for (let w = 0; w < windows; w++) for (let byte = 0; byte < windowSize; byte++) {
			let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
			for (let j = 0; j < W; j++) {
				if (!(byte >>> W - j - 1 & 1)) continue;
				const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
				s0 ^= d0, s1 ^= d1, s2 ^= d2, s3 ^= d3;
			}
			items.push({
				s0,
				s1,
				s2,
				s3
			});
		}
		this.t = items;
	}
	_updateBlock(s0, s1, s2, s3) {
		s0 ^= this.s0, s1 ^= this.s1, s2 ^= this.s2, s3 ^= this.s3;
		const { W, t, windowSize } = this;
		let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
		const mask = (1 << W) - 1;
		let w = 0;
		for (const num of [
			s0,
			s1,
			s2,
			s3
		]) for (let bytePos = 0; bytePos < 4; bytePos++) {
			const byte = num >>> 8 * bytePos & 255;
			for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
				const bit = byte >>> W * bitPos & mask;
				const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
				o0 ^= e0, o1 ^= e1, o2 ^= e2, o3 ^= e3;
				w += 1;
			}
		}
		this.s0 = o0;
		this.s1 = o1;
		this.s2 = o2;
		this.s3 = o3;
	}
	update(data) {
		aexists(this);
		abytes(data);
		data = copyBytes(data);
		const b32 = u32(data);
		const blocks = Math.floor(data.length / BLOCK_SIZE$1);
		const left = data.length % BLOCK_SIZE$1;
		for (let i = 0; i < blocks; i++) this._updateBlock(swap8IfBE(b32[i * 4 + 0]), swap8IfBE(b32[i * 4 + 1]), swap8IfBE(b32[i * 4 + 2]), swap8IfBE(b32[i * 4 + 3]));
		if (left) {
			ZEROS16.set(data.subarray(blocks * BLOCK_SIZE$1));
			this._updateBlock(swap8IfBE(ZEROS32[0]), swap8IfBE(ZEROS32[1]), swap8IfBE(ZEROS32[2]), swap8IfBE(ZEROS32[3]));
			clean(ZEROS32);
		}
		return this;
	}
	destroy() {
		this.destroyed = true;
		const { t } = this;
		for (const elm of t) elm.s0 = 0, elm.s1 = 0, elm.s2 = 0, elm.s3 = 0;
	}
	digestInto(out) {
		aexists(this);
		aoutput32(out, this);
		this.finished = true;
		const { s0, s1, s2, s3 } = this;
		const o32 = u32(out);
		o32[0] = s0;
		o32[1] = s1;
		o32[2] = s2;
		o32[3] = s3;
		if (!isLE) swap32IfBE(o32.subarray(0, BLOCK_SIZE$1 / 4));
	}
	digest() {
		const res = new Uint8Array(BLOCK_SIZE$1);
		this.digestInto(res);
		this.destroy();
		return res;
	}
};
/**
* Incremental POLYVAL state for AES-SIV.
* @param key - 16-byte POLYVAL key.
* @param expectedLength - Expected message length for table sizing.
* Inherits GHASH's segment-padded `update()` behavior: each call is padded
* independently to a 16-byte boundary before absorption.
* @example
* Feeds one block into an incremental POLYVAL state with a fresh hash key.
*
* ```ts
* import { Polyval } from '@noble/ciphers/_polyval.js';
* import { randomBytes } from '@noble/ciphers/utils.js';
* const key = randomBytes(16);
* const mac = new Polyval(key);
* mac.update(new Uint8Array(16));
* mac.digest();
* ```
*/
var Polyval = class extends GHASH {
	constructor(key, expectedLength) {
		abytes(key);
		const ghKey = _toGHASHKey(copyBytes(key));
		super(ghKey, expectedLength);
		clean(ghKey);
	}
	update(data) {
		aexists(this);
		abytes(data);
		data = copyBytes(data);
		const b32 = u32(data);
		const left = data.length % BLOCK_SIZE$1;
		const blocks = Math.floor(data.length / BLOCK_SIZE$1);
		for (let i = 0; i < blocks; i++) this._updateBlock(swap8IfLE(b32[i * 4 + 3]), swap8IfLE(b32[i * 4 + 2]), swap8IfLE(b32[i * 4 + 1]), swap8IfLE(b32[i * 4 + 0]));
		if (left) {
			ZEROS16.set(data.subarray(blocks * BLOCK_SIZE$1));
			this._updateBlock(swap8IfLE(ZEROS32[3]), swap8IfLE(ZEROS32[2]), swap8IfLE(ZEROS32[1]), swap8IfLE(ZEROS32[0]));
			clean(ZEROS32);
		}
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput32(out, this);
		this.finished = true;
		const view = out.subarray(0, this.outputLen);
		const { s0, s1, s2, s3 } = this;
		const o32 = u32(view);
		o32[0] = s0;
		o32[1] = s1;
		o32[2] = s2;
		o32[3] = s3;
		swap32IfBE(o32);
		view.reverse();
	}
};
/**
* POLYVAL MAC for AES-SIV.
* @param msg - Message bytes to authenticate.
* @param key - 16-byte POLYVAL key.
* @returns 16-byte authentication tag.
* @example
* Authenticates a short message with POLYVAL and a fresh hash key.
*
* ```ts
* import { polyval } from '@noble/ciphers/_polyval.js';
* import { randomBytes } from '@noble/ciphers/utils.js';
* const key = randomBytes(16);
* polyval(new Uint8Array(), key);
* ```
*/
var polyval = /* @__PURE__ */ wrapMacConstructor(16, (key, expectedLength) => new Polyval(key, expectedLength), (msg) => [msg.length]);
//#endregion
//#region node_modules/@noble/ciphers/aes.js
var BLOCK_SIZE = 16;
var BLOCK_SIZE32 = 4;
var EMPTY_BLOCK = /* @__PURE__ */ new Uint8Array(BLOCK_SIZE);
var ONE_BLOCK = /* @__PURE__ */ Uint8Array.from([
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	1
]);
var POLY = 283;
function validateKeyLength(key) {
	if (![
		16,
		24,
		32
	].includes(key.length)) throw new Error("\"aes key\" expected Uint8Array of length 16/24/32, got length=" + key.length);
}
function mul2(n) {
	return n << 1 ^ POLY & -(n >> 7);
}
function mul(a, b) {
	let res = 0;
	for (; b > 0; b >>= 1) {
		res ^= a & -(b & 1);
		a = mul2(a);
	}
	return res;
}
var sbox = /* @__PURE__ */ (() => {
	const t = /* @__PURE__ */ new Uint8Array(256);
	for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x)) t[i] = x;
	const box = /* @__PURE__ */ new Uint8Array(256);
	box[0] = 99;
	for (let i = 0; i < 255; i++) {
		let x = t[255 - i];
		x |= x << 8;
		box[t[i]] = (x ^ x >> 4 ^ x >> 5 ^ x >> 6 ^ x >> 7 ^ 99) & 255;
	}
	clean(t);
	return box;
})();
var invSbox = /* @__PURE__ */ sbox.map((_, j) => sbox.indexOf(j));
var rotr32_8 = (n) => n << 24 | n >>> 8;
var rotl32_8 = (n) => n << 8 | n >>> 24;
function genTtable(sbox, fn) {
	if (sbox.length !== 256) throw new Error("wrong sbox length");
	const T0 = (/* @__PURE__ */ new Uint32Array(256)).map((_, j) => fn(sbox[j]));
	const T1 = T0.map(rotl32_8);
	const T2 = T1.map(rotl32_8);
	const T3 = T2.map(rotl32_8);
	const T01 = /* @__PURE__ */ new Uint32Array(65536);
	const T23 = /* @__PURE__ */ new Uint32Array(65536);
	const sbox2 = /* @__PURE__ */ new Uint16Array(65536);
	for (let i = 0; i < 256; i++) for (let j = 0; j < 256; j++) {
		const idx = i * 256 + j;
		T01[idx] = T0[i] ^ T1[j];
		T23[idx] = T2[i] ^ T3[j];
		sbox2[idx] = sbox[i] << 8 | sbox[j];
	}
	return {
		sbox,
		sbox2,
		T0,
		T1,
		T2,
		T3,
		T01,
		T23
	};
}
var tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => mul(s, 3) << 24 | s << 16 | s << 8 | mul(s, 2));
var tableDecoding = /* @__PURE__ */ genTtable(invSbox, (s) => mul(s, 11) << 24 | mul(s, 13) << 16 | mul(s, 9) << 8 | mul(s, 14));
var xPowers = /* @__PURE__ */ (() => {
	const p = /* @__PURE__ */ new Uint8Array(16);
	for (let i = 0, x = 1; i < 16; i++, x = mul2(x)) p[i] = x;
	return p;
})();
/** Forward AES key expansion used across ECB/CBC/CTR/GCM/CMAC/KW-style paths. */
function expandKeyLE(key) {
	abytes(key);
	const len = key.length;
	validateKeyLength(key);
	const { sbox2 } = tableEncoding;
	const toClean = [];
	if (!isLE || !isAligned32(key)) toClean.push(key = copyBytes(key));
	const k32 = swap32IfBE(u32(key));
	const Nk = k32.length;
	const subByte = (n) => applySbox(sbox2, n, n, n, n);
	const xk = new Uint32Array(len + 28);
	xk.set(k32);
	for (let i = Nk; i < xk.length; i++) {
		let t = xk[i - 1];
		if (i % Nk === 0) t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
		else if (Nk > 6 && i % Nk === 4) t = subByte(t);
		xk[i] = xk[i - Nk] ^ t;
	}
	clean(...toClean);
	return xk;
}
function expandKeyDecLE(key) {
	const encKey = expandKeyLE(key);
	const xk = encKey.slice();
	const Nk = encKey.length;
	const { sbox2 } = tableEncoding;
	const { T0, T1, T2, T3 } = tableDecoding;
	for (let i = 0; i < Nk; i += 4) for (let j = 0; j < 4; j++) xk[i + j] = encKey[Nk - i - 4 + j];
	clean(encKey);
	for (let i = 4; i < Nk - 4; i++) {
		const x = xk[i];
		const w = applySbox(sbox2, x, x, x, x);
		xk[i] = T0[w & 255] ^ T1[w >>> 8 & 255] ^ T2[w >>> 16 & 255] ^ T3[w >>> 24];
	}
	return xk;
}
function apply0123(T01, T23, s0, s1, s2, s3) {
	return T01[s0 << 8 & 65280 | s1 >>> 8 & 255] ^ T23[s2 >>> 8 & 65280 | s3 >>> 24 & 255];
}
function applySbox(sbox2, s0, s1, s2, s3) {
	return sbox2[s0 & 255 | s1 & 65280] | sbox2[s2 >>> 16 & 255 | s3 >>> 16 & 65280] << 16;
}
function encrypt(xk, s0, s1, s2, s3) {
	const { sbox2, T01, T23 } = tableEncoding;
	let k = 0;
	s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
	const rounds = xk.length / 4 - 2;
	for (let i = 0; i < rounds; i++) {
		const t0 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
		const t1 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
		const t2 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
		const t3 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
		s0 = t0, s1 = t1, s2 = t2, s3 = t3;
	}
	return {
		s0: xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3),
		s1: xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0),
		s2: xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1),
		s3: xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2)
	};
}
function decrypt(xk, s0, s1, s2, s3) {
	const { sbox2, T01, T23 } = tableDecoding;
	let k = 0;
	s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
	const rounds = xk.length / 4 - 2;
	for (let i = 0; i < rounds; i++) {
		const t0 = xk[k++] ^ apply0123(T01, T23, s0, s3, s2, s1);
		const t1 = xk[k++] ^ apply0123(T01, T23, s1, s0, s3, s2);
		const t2 = xk[k++] ^ apply0123(T01, T23, s2, s1, s0, s3);
		const t3 = xk[k++] ^ apply0123(T01, T23, s3, s2, s1, s0);
		s0 = t0, s1 = t1, s2 = t2, s3 = t3;
	}
	return {
		s0: xk[k++] ^ applySbox(sbox2, s0, s3, s2, s1),
		s1: xk[k++] ^ applySbox(sbox2, s1, s0, s3, s2),
		s2: xk[k++] ^ applySbox(sbox2, s2, s1, s0, s3),
		s3: xk[k++] ^ applySbox(sbox2, s3, s2, s1, s0)
	};
}
function ctrCounter(xk, nonce, src, dst) {
	abytes(nonce, BLOCK_SIZE, "nonce");
	abytes(src);
	const srcLen = src.length;
	dst = getOutput(srcLen, dst);
	complexOverlapBytes(src, dst);
	const ctr = nonce;
	const c32 = u32(ctr);
	const src32 = u32(src);
	const dst32 = u32(dst);
	for (let i = 0; i + 4 <= src32.length; i += 4) {
		const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
		dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
		dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
		dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
		dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
		for (let j = 15, carry = 1; j >= 0; j--) {
			carry = carry + ctr[j] | 0;
			ctr[j] = carry & 255;
			carry >>>= 8;
		}
	}
	const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
	if (start < srcLen) {
		const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
		const b32 = new Uint32Array([
			s0,
			s1,
			s2,
			s3
		]);
		swap32IfBE(b32);
		const buf = u8(b32);
		for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos];
		clean(b32);
	}
	return dst;
}
function ctr32(xk, isLE, nonce, src, dst) {
	abytes(nonce, BLOCK_SIZE, "nonce");
	abytes(src);
	dst = getOutput(src.length, dst);
	const ctr = nonce;
	const c32 = u32(ctr);
	const view = createView(ctr);
	const src32 = u32(src);
	const dst32 = u32(dst);
	const ctrPos = isLE ? 0 : 12;
	const srcLen = src.length;
	let ctrNum = view.getUint32(ctrPos, isLE);
	for (let i = 0; i + 4 <= src32.length; i += 4) {
		const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
		dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
		dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
		dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
		dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
		ctrNum = ctrNum + 1 >>> 0;
		view.setUint32(ctrPos, ctrNum, isLE);
	}
	const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
	if (start < srcLen) {
		const { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
		const b32 = new Uint32Array([
			s0,
			s1,
			s2,
			s3
		]);
		swap32IfBE(b32);
		const buf = u8(b32);
		for (let i = start, pos = 0; i < srcLen; i++, pos++) dst[i] = src[i] ^ buf[pos];
		clean(b32);
	}
	return dst;
}
/**
* **CTR** (Counter Mode): turns a block cipher into a stream cipher using a
* full 16-byte counter block.
* Efficient and parallelizable. Requires a unique nonce per encryption. Unauthenticated: needs MAC.
* @param key - AES key bytes.
* @param nonce - 16-byte counter block, incremented as a full AES block.
* @returns Cipher instance with `encrypt()` and `decrypt()`.
* @example
* Encrypts a short payload with a fresh AES key and counter block.
*
* ```ts
* import { ctr } from '@noble/ciphers/aes.js';
* import { randomBytes } from '@noble/ciphers/utils.js';
* const key = randomBytes(16);
* const nonce = randomBytes(16);
* const cipher = ctr(key, nonce);
* cipher.encrypt(new Uint8Array([1, 2, 3]));
* ```
*/
var ctr = /* @__PURE__ */ wrapCipher({
	blockSize: 16,
	nonceLength: 16
}, function aesctr(key, nonce) {
	function processCtr(buf, dst) {
		abytes(buf);
		if (dst !== void 0) {
			abytes(dst);
			if (!isAligned32(dst)) throw new Error("unaligned destination");
		}
		const xk = expandKeyLE(key);
		const n = copyBytes(nonce);
		const toClean = [xk, n];
		if (!isAligned32(buf)) toClean.push(buf = copyBytes(buf));
		const out = ctrCounter(xk, n, buf, dst);
		clean(...toClean);
		return out;
	}
	return {
		encrypt: (plaintext, dst) => processCtr(plaintext, dst),
		decrypt: (ciphertext, dst) => processCtr(ciphertext, dst)
	};
});
function isBytes32(a) {
	return a instanceof Uint32Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint32Array";
}
function encryptBlock(xk, block) {
	abytes(block, 16, "block");
	if (!isBytes32(xk)) throw new Error("_encryptBlock accepts result of expandKeyLE");
	const b32 = u32(block);
	swap32IfBE(b32);
	let { s0, s1, s2, s3 } = encrypt(xk, b32[0], b32[1], b32[2], b32[3]);
	b32[0] = s0, b32[1] = s1, b32[2] = s2, b32[3] = s3;
	swap32IfBE(b32);
	return block;
}
function decryptBlock(xk, block) {
	abytes(block, 16, "block");
	if (!isBytes32(xk)) throw new Error("_decryptBlock accepts result of expandKeyLE");
	const b32 = u32(block);
	swap32IfBE(b32);
	let { s0, s1, s2, s3 } = decrypt(xk, b32[0], b32[1], b32[2], b32[3]);
	b32[0] = s0, b32[1] = s1, b32[2] = s2, b32[3] = s3;
	swap32IfBE(b32);
	return block;
}
/**
* Left-shift by one bit and conditionally XOR with 0x87:
* ```
* if MSB(L) is equal to 0
* then    K1 := L << 1;
* else    K1 := (L << 1) XOR const_Rb;
* ```
*
* Specs:
* {@link https://www.rfc-editor.org/rfc/rfc4493.html#section-2.3 | RFC 4493 Section 2.3},
* {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.3 | RFC 5297 Section 2.3}
*
* @returns modified `block` (for chaining)
*/
function dbl(block) {
	let carry = 0;
	for (let i = 15; i >= 0; i--) {
		const newCarry = (block[i] & 128) >>> 7;
		block[i] = block[i] << 1 | carry;
		carry = newCarry;
	}
	block[15] ^= 135 & -carry;
	return block;
}
/**
* `a XOR b`, running in-place on `a`.
* @param a left operand and output
* @param b right operand
* @returns `a` (for chaining)
*/
function xorBlock(a, b) {
	if (a.length !== b.length) throw new Error("xorBlock: blocks must have same length");
	for (let i = 0; i < a.length; i++) a[i] = a[i] ^ b[i];
	return a;
}
/**
* xorend as defined in
* {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.1 | RFC 5297 Section 2.1}.
*
* ```
* leftmost(A, len(A)-len(B)) || (rightmost(A, len(B)) xor B)
* ```
*
* Mutates `a` in place so the left prefix stays untouched and only the
* rightmost `len(B)` bytes are xored with `b`.
*/
function xorend(a, b) {
	if (b.length > a.length) throw new Error("xorend: expected len(B) <= len(A)");
	const offset = a.length - b.length;
	for (let i = 0; i < b.length; i++) a[offset + i] = a[offset + i] ^ b[i];
	return a;
}
/**
* Internal CMAC class.
*/
var _CMAC = class {
	blockLen = BLOCK_SIZE;
	outputLen = BLOCK_SIZE;
	buffer;
	pos;
	finished;
	destroyed;
	k1;
	k2;
	x;
	x32;
	xk;
	constructor(key) {
		abytes(key);
		validateKeyLength(key);
		this.xk = expandKeyLE(key);
		this.buffer = new Uint8Array(BLOCK_SIZE);
		this.pos = 0;
		this.finished = false;
		this.destroyed = false;
		this.x = new Uint8Array(BLOCK_SIZE);
		this.x32 = u32(this.x);
		const L = new Uint8Array(BLOCK_SIZE);
		encryptBlock(this.xk, L);
		this.k1 = dbl(L);
		this.k2 = dbl(new Uint8Array(this.k1));
	}
	process(data, pos) {
		const { x, x32, xk } = this;
		for (let i = 0; i < BLOCK_SIZE; i++) x[i] ^= data[pos + i];
		swap32IfBE(x32);
		const { s0, s1, s2, s3 } = encrypt(xk, x32[0], x32[1], x32[2], x32[3]);
		x32[0] = s0, x32[1] = s1, x32[2] = s2, x32[3] = s3;
		swap32IfBE(x32);
	}
	update(data) {
		aexists(this);
		abytes(data);
		let pos = 0;
		if (this.pos) {
			const take = Math.min(BLOCK_SIZE - this.pos, data.length);
			this.buffer.set(data.subarray(0, take), this.pos);
			this.pos += take;
			pos = take;
			if (this.pos === BLOCK_SIZE && pos < data.length) {
				this.process(this.buffer, 0);
				this.pos = 0;
			}
		}
		while (pos + BLOCK_SIZE < data.length) {
			this.process(data, pos);
			pos += BLOCK_SIZE;
		}
		if (pos < data.length) {
			this.buffer.set(data.subarray(pos), 0);
			this.pos = data.length - pos;
		}
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput32(out, this);
		this.finished = true;
		const view = out.subarray(0, this.outputLen);
		let last = new Uint8Array(BLOCK_SIZE);
		if (this.pos === BLOCK_SIZE) {
			last.set(this.buffer);
			xorBlock(last, this.k1);
		} else {
			last.set(this.buffer.subarray(0, this.pos));
			last[this.pos] = 128;
			xorBlock(last, this.k2);
		}
		view.set(this.x);
		xorBlock(view, last);
		encryptBlock(this.xk, view);
		clean(last);
	}
	digest() {
		const { buffer, outputLen } = this;
		this.digestInto(buffer);
		const res = buffer.slice(0, outputLen);
		this.destroy();
		return res;
	}
	destroy() {
		const { buffer, destroyed, x, xk, k1, k2 } = this;
		if (destroyed) return;
		this.destroyed = true;
		clean(buffer, x, xk, k1, k2);
	}
};
/**
* AES-CMAC (Cipher-based Message Authentication Code).
* Specs: {@link https://www.rfc-editor.org/rfc/rfc4493.html | RFC 4493}.
* @param msg - Message bytes to authenticate.
* @param key - AES key bytes.
* @returns 16-byte authentication tag. `cmac.create(...)` follows the same incremental MAC shape as
* the other keyed helpers in this repo, including `blockLen`,
* `outputLen`, `digestInto()` and `destroy()`.
* @example
* Authenticates a message with AES-CMAC and a fresh key.
*
* ```ts
* import { cmac } from '@noble/ciphers/aes.js';
* import { randomBytes } from '@noble/ciphers/utils.js';
* const key = randomBytes(16);
* cmac(new Uint8Array(), key);
* ```
*/
var cmac = /* @__PURE__ */ wrapMacConstructor(16, (key) => new _CMAC(key));
/**
* S2V (Synthetic Initialization Vector) function as described in
* {@link https://datatracker.ietf.org/doc/html/rfc5297.html#section-2.4 | RFC 5297 Section 2.4}.
*
* ```
* S2V(K, S1, ..., Sn) {
*   if n = 0 then
*     return V = AES-CMAC(K, <one>)
*   fi
*   D = AES-CMAC(K, <zero>)
*   for i = 1 to n-1 do
*     D = dbl(D) xor AES-CMAC(K, Si)
*   done
*   if len(Sn) >= 128 then
*     T = Sn xorend D
*   else
*     T = dbl(D) xor pad(Sn)
*   fi
*   return V = AES-CMAC(K, T)
* }
* ```
*
* S2V takes a key and a vector of strings S1, S2, ..., Sn and returns a 128-bit string.
* The S2V function is used to generate a synthetic IV for AES-SIV.
*
* @param key - AES key (128, 192, or 256 bits)
* @param strings - Array of byte arrays to process
* @returns 128-bit synthetic IV
*/
function s2v(key, strings) {
	validateKeyLength(key);
	const len = strings.length;
	if (len > 127) throw new Error("s2v: expected <= 127 inputs");
	if (len === 0) return cmac(ONE_BLOCK, key);
	let d = cmac(EMPTY_BLOCK, key);
	for (let i = 0; i < len - 1; i++) {
		dbl(d);
		const cmacResult = cmac(strings[i], key);
		xorBlock(d, cmacResult);
		clean(cmacResult);
	}
	const s_n = strings[len - 1];
	abytes(s_n);
	let t;
	if (s_n.byteLength >= BLOCK_SIZE) t = xorend(Uint8Array.from(s_n), d);
	else {
		const paddedSn = new Uint8Array(BLOCK_SIZE);
		paddedSn.set(s_n);
		paddedSn[s_n.length] = 128;
		t = xorBlock(dbl(d), paddedSn);
		clean(paddedSn);
	}
	const result = cmac(t, key);
	clean(d, t);
	return result;
}
/**
* Unsafe low-level internal methods. May change at any time.
* Callers are expected to use reviewed expanded-key outputs, pass mutable and
* aligned 16-byte blocks where required, and treat several helpers as in-place
* mutations of their input buffers or counters.
*/
var unsafe = /* @__PURE__ */ Object.freeze({
	expandKeyLE,
	expandKeyDecLE,
	encrypt,
	decrypt,
	encryptBlock,
	decryptBlock,
	ctrCounter,
	ctr32,
	dbl,
	xorBlock,
	xorend,
	s2v
});
//#endregion
export { unsafe as n, polyval as r, ctr as t };
