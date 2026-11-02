import assert from "node:assert/strict";
import { cidrContains, defaultProfile, exportedConfig, importClashRules, importSingBox, matchRoute, normalizeProfile, profileIssues } from "./profile.ts";

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
assert.equal(upgraded.link.maxConns, 128);
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

console.log("profile ok");
