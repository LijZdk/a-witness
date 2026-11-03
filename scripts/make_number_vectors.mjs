// Generates testdata/vectors/numbers.json: how RFC 8785 writes IEEE 754 doubles.
//
// RFC 8785 defines number formatting as ECMAScript's Number.prototype.toString,
// so the expected outputs come from the JavaScript engine itself, not from any
// a-witness implementation. Run with: node scripts/make_number_vectors.mjs
//
// The inputs are deterministic (fixed list plus a seeded generator), so the
// file only changes if this script does.
import { writeFileSync } from "node:fs";

const view = new DataView(new ArrayBuffer(8));
const MASK = (1n << 64n) - 1n;
const toFloat = (bits) => { view.setBigUint64(0, bits); return view.getFloat64(0); };
const toBits = (f) => { view.setFloat64(0, f); return view.getBigUint64(0); };

const vectors = [];
const seen = new Set();
function add(bits) {
  bits &= MASK;
  const f = toFloat(bits);
  const hex = bits.toString(16).padStart(16, "0");
  if (!Number.isFinite(f) || seen.has(hex)) return;
  seen.add(hex);
  vectors.push({ bits: hex, output: JSON.stringify(f) });
}

// 1. The examples from RFC 8785 Appendix B.
for (const hex of [
  "0000000000000000", "8000000000000000", "0000000000000001", "8000000000000001",
  "7fefffffffffffff", "ffefffffffffffff", "4340000000000000", "c340000000000000",
  "4430000000000000", "44b52d02c7e14af5", "44b52d02c7e14af6", "44b52d02c7e14af7",
  "444b1ae4d6e2ef4e", "444b1ae4d6e2ef4f", "444b1ae4d6e2ef50", "3eb0c6f7a0b5ed8c",
  "3eb0c6f7a0b5ed8d", "41b3de4355555553", "41b3de4355555554", "41b3de4355555555",
  "41b3de4355555556", "41b3de4355555557", "becbf647612f3696", "43143ff3c1cb0959",
]) add(BigInt("0x" + hex));

// 2. Powers of ten and their immediate neighbours, where the notation switches
//    between plain and exponent form (at 1e-7 and 1e21).
for (let p = -30; p <= 30; p++) {
  const b = toBits(Number(`1e${p}`));
  for (const d of [-1n, 0n, 1n]) { add(b + d); add((b + d) | (1n << 63n)); }
}

// 3. Small integers, and integers around 2^53 where doubles stop being exact.
for (const n of [1, 2, 9, 10, 99, 100, 255, 1000, 65535, 1e6]) add(toBits(n));
const twoTo53 = toBits(2 ** 53);
for (let d = -3n; d <= 3n; d++) add(twoTo53 + d);

// 4. Seeded pseudo-random doubles (splitmix64): first with any exponent,
//    then with exponents near 1, where everyday values such as prices live.
let state = 0x5eeda817e55n; // fixed seed, so the vectors are reproducible
function next() {
  state = (state + 0x9e3779b97f4a7c15n) & MASK;
  let z = state;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;
  return z ^ (z >> 31n);
}
for (let i = 0; i < 400; i++) add(next());
for (let i = 0; i < 800; i++) {
  const r = next();
  const exponent = 1023n - 80n + (r % 161n); // about 1e-24 to 1e24
  add(((r >> 63n) << 63n) | (exponent << 52n) | (next() & ((1n << 52n) - 1n)));
}

const header = {
  description: "RFC 8785 number formatting. Each vector is an IEEE 754 double, given as 16 hex digits of its bit pattern, and the exact text RFC 8785 requires for it.",
  generated_by: "scripts/make_number_vectors.mjs, using the ECMAScript engine's own JSON.stringify",
  count: vectors.length,
};
const lines = vectors.map((v) => "    " + JSON.stringify(v));
const text = JSON.stringify(header, null, 2).replace(/\n}$/, ",\n  \"vectors\": [\n" + lines.join(",\n") + "\n  ]\n}\n");
writeFileSync(new URL("../testdata/vectors/numbers.json", import.meta.url), text);
console.log(`wrote ${vectors.length} number vectors`);
