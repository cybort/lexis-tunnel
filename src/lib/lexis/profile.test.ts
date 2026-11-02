import assert from "node:assert/strict";
import { cidrContains, defaultProfile, estimateTokenBits, exportedConfig, importClashRules, importSingBox, matchRoute, mintHandshakeToken, normalizeProfile, profileIssues } from "./profile.ts";

const profile = defaultProfile();

assert.equal(matchRoute(profile, { host: "www.baidu.com" }).action, "direct");
assert.equal(matchRoute(profile, { host: "mail.google.com" }).action, "proxy");
assert.equal(matchRoute(profile, { ip: "10.1.2.3" }).action, "direct");
assert.equal(matchRoute(profile, { ip: "114.114.114.114" }).action, "direct");
assert.equal(matchRoute(profile, { host: "example.com", process: "ssh.exe" }).action, "bypass");
assert.equal(cidrContains("172.16.0.0/12", "172.31.255.1"), true);
assert.equal(cidrContains("172.16.0.0/12", "172.32.0.1"), false);

const clash = importClashRules(`
rules:
 - GEOSITE,telegram,PROXY
 - PROCESS-NAME,firefox,BYPASS
 - MATCH,DIRECT
`);
assert.equal(clash[0].type, "GEOSITE");
assert.equal(clash[1].action, "bypass");
assert.equal(clash[2].type, "MATCH");
assert.equal(clash[2].action, "direct");

const sing = importSingBox(`{
  "route": { "rules": [
    { "domain_suffix": ["example.com"], "outbound": "proxy" },
    { "geoip": "cn", "outbound": "direct" },
    { "process_name": ["Code.exe"], "outbound": "reject" }
  ]}
}`);
assert.equal(sing[0].type, "DOMAIN-SUFFIX");
assert.equal(sing[1].type, "GEOIP");
assert.equal(sing[2].action, "reject");

const custom = {
  ...profile,
  extras: "google intranet.example\ngeoip:cn 203.0.113.0/24",
  rules: [{ id: "g", type: "GEOSITE" as const, value: "google", action: "direct" as const }, ...profile.rules],
};
assert.equal(matchRoute(custom, { host: "a.intranet.example" }).action, "direct");
assert.equal(matchRoute(custom, { ip: "203.0.113.9" }).action, "direct");

const upgraded = normalizeProfile({ version: 1, role: "gate" });
assert.equal(upgraded.link.idleMs, 120000);
assert.equal(upgraded.link.maxConns, 1024);
assert.equal(upgraded.egress.blockPrivate, true);
assert.equal(upgraded.outer.transport, "tcp");
assert.equal(upgraded.outer.wsPath, "/lexis");
assert.equal(upgraded.identity, null);
assert.equal(upgraded.seal, null);
assert.equal(normalizeProfile({ kdf: { memoryKiB: 65536, iterations: 3, parallelism: 1 } }).kdf.memoryKiB, 16384);
const coeff = "AAAAAAAAAAAAAAAAAAAAAA==";
const sealed = normalizeProfile({
  seal: {
    saltB64: coeff,
    memoryKiB: 65536,
    iterations: 3,
    parallelism: 1,
    lo: { saltB64: coeff, coeffsB64: [coeff] },
    hi: { saltB64: coeff, coeffsB64: [coeff] },
  },
});
assert.equal(sealed.seal?.memoryKiB, 65536);
assert.equal(normalizeProfile({ seal: { saltB64: "aa" } }).seal, null);
const identity = {
  id: "i",
  name: "本机",
  publicJwk: { kty: "EC", crv: "P-256", x: "aa", y: "bb" },
  privateJwk: { kty: "EC", crv: "P-256", x: "aa", y: "bb", d: "secret" },
  publicRawB64: "aa",
  fingerprint: "fp",
};
const published = exportedConfig({ ...defaultProfile(), seal: sealed.seal, identity });
assert.equal(published.seal, null);
assert.equal(published.identity?.privateJwk.d, undefined);
assert.equal(published.identity?.publicJwk.x, "aa");
assert.equal(exportedConfig({ ...defaultProfile(), identity }).identity?.privateJwk.d, "secret");
assert.equal(profileIssues(upgraded).some((item) => item.includes("身份")), true);
assert.equal(defaultProfile().role, "edge");
assert.equal(normalizeProfile({}).role, "");
assert.equal(normalizeProfile({ role: "nope" }).role, "");
assert.equal(normalizeProfile({ role: "edge" }).role, "edge");
assert.equal(profileIssues(normalizeProfile({})).some((item) => item.includes("角色")), true);
assert.equal(normalizeProfile({ statusToken: "abc" }).statusToken, "abc");
const wide = normalizeProfile({ role: "edge", statusHost: "0.0.0.0" });
assert.equal(profileIssues(wide).some((item) => item.includes("状态口令")), true);
assert.equal(profileIssues(normalizeProfile({ role: "edge", statusHost: "0.0.0.0", statusToken: "x" })).some((item) => item.includes("状态口令")), false);
assert.equal(defaultProfile().frame.maxExpansion, 5);
assert.equal(defaultProfile().frame.smallFramePolicy, "expansion");
assert.equal(defaultProfile().frame.coalesceTarget, 1024);
assert.equal(defaultProfile().link.udpIdleMs, 60000);
assert.equal(defaultProfile().link.udpMax, 64);
assert.equal(defaultProfile().link.maxHalfOpen, 512);
assert.equal(defaultProfile().link.halfOpenPrefixV4, 24);
assert.equal(defaultProfile().link.halfOpenPrefixV6, 64);
assert.equal(defaultProfile().link.maxSilent, 1024);
assert.equal(defaultProfile().link.firstByteMs, 2000);
assert.equal(defaultProfile().link.maxHalfOpenPerIp, 8);
const framed = normalizeProfile({ frame: { maxExpansion: 99, smallFramePolicy: "honey", coalesceTarget: 8 }, link: { udpIdleMs: 50, udpMax: 1 } });
assert.equal(framed.frame.maxExpansion, 5);
assert.equal(framed.frame.smallFramePolicy, "honey");
assert.equal(framed.frame.coalesceTarget, 1024);
assert.equal(framed.link.udpIdleMs, 60000);
assert.equal(framed.link.udpMax, 64);
assert.ok(estimateTokenBits(mintHandshakeToken()) >= 128);
const weakJoin = normalizeProfile({
  role: "gate",
  peers: [{ id: "p", name: "n", endpoint: "203.0.113.8:18443", publicRawB64: "abcdabcdabcdabcd" }],
  link: { token: "short-token" },
});
assert.equal(profileIssues(weakJoin).some((item) => item.includes("128")), true);
const strongJoin = normalizeProfile({ ...weakJoin, link: { ...weakJoin.link, token: mintHandshakeToken() } });
assert.equal(profileIssues(strongJoin).some((item) => item.includes("口令")), false);

console.log("profile ok");
{
  const p = normalizeProfile({ link: { halfOpenPrefixV4: 16, halfOpenPrefixV6: 48, maxSilent: 0, firstByteMs: 0 } });
  assert.deepEqual([p.link.halfOpenPrefixV4, p.link.halfOpenPrefixV6, p.link.maxSilent, p.link.firstByteMs], [16, 48, 0, 0]);
  const bad = normalizeProfile({ link: { halfOpenPrefixV4: 33, halfOpenPrefixV6: 129, maxSilent: -1, firstByteMs: 1.5 } });
  assert.deepEqual([bad.link.halfOpenPrefixV4, bad.link.halfOpenPrefixV6, bad.link.maxSilent, bad.link.firstByteMs], [24, 64, 1024, 2000]);
  const tight = normalizeProfile({ link: { maxConns: 128, maxHalfOpen: 512 } });
  assert.equal(profileIssues(tight).some((item) => item.includes("连接上限")), true);
  assert.equal(profileIssues(defaultProfile()).some((item) => item.includes("连接上限")), false);
  console.log("profile half-open fields ok");
}
