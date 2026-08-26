/**
 * MSISDN hash decoder
 * -------------------
 * Safaricom masks the customer's phone number in C2B / Buy Goods callbacks by
 * sending SHA-256("2547XXXXXXXX") instead of the real number (Data Protection
 * Act 2019). The hash is UNSALTED and deterministic, so we can reverse it by
 * brute-forcing the (finite) set of valid Safaricom mobile numbers.
 *
 * Verified: SHA-256("254705708643") === the hash we received for "Joyce".
 *
 * The scan is offloaded to a background Worker Thread so it never blocks the
 * event loop, and results are memoised so a repeat customer resolves instantly.
 */
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

// Safaricom mobile prefixes (the 3 digits after the 254 country code), ordered
// roughly by how common they are so typical numbers resolve fastest. Each
// prefix expands to 1,000,000 numbers (prefix + 6 digits).
const SAF_PREFIXES = [];
for (let p = 700; p <= 729; p++) SAF_PREFIXES.push(String(p));            // 0700–0729
for (const p of [740,741,742,743,744,745,746,748,757,758,759,768,769,763, // 0740s/0750s/0760s
                 790,791,792,793,794,795,796,797,798,799,                  // 0790–0799
                 110,111,112,113,114,115,116,117,118,119]) {              // 0110–0119
  SAF_PREFIXES.push(String(p));
}

if (isMainThread) {
  const memCache = new Map();   // hash -> "2547XXXXXXXX" | null
  const inFlight = new Map();   // hash -> Promise (dedupe concurrent decodes)

  // A simple queue to run decodes sequentially (max 1 running worker at a time)
  const queue = [];
  let activeWorkerCount = 0;

  function processQueue() {
    if (activeWorkerCount > 0 || queue.length === 0) return;
    activeWorkerCount++;
    const { hash, resolve, reject } = queue.shift();

    const worker = new Worker(__filename, {
      workerData: { hash }
    });

    let resolved = false;

    worker.on('message', (msisdn) => {
      resolved = true;
      memCache.set(hash, msisdn);
      resolve(msisdn);
    });

    worker.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        reject(err);
      }
    });

    worker.on('exit', (code) => {
      activeWorkerCount--;
      if (!resolved) {
        resolved = true;
        memCache.set(hash, null);
        resolve(null);
      }
      // Process the next job in the queue
      processQueue();
    });
  }

  function looksHashed(s) {
    return /^[a-f0-9]{64}$/i.test(String(s || ''));
  }

  // Reverse a single hashed MSISDN. Returns "2547XXXXXXXX" or null if not found.
  function decodeHash(rawHash) {
    const hash = String(rawHash || '').toLowerCase();
    if (!looksHashed(hash)) return Promise.resolve(null);
    if (memCache.has(hash)) return Promise.resolve(memCache.get(hash));
    if (inFlight.has(hash)) return inFlight.get(hash);

    const promise = new Promise((resolve, reject) => {
      queue.push({ hash, resolve, reject });
      processQueue();
    });

    inFlight.set(hash, promise);
    promise.finally(() => {
      inFlight.delete(hash);
    });

    return promise;
  }

  // Seed the in-memory cache (e.g. from a persistent store) to skip brute force.
  function primeCache(hash, msisdn) {
    if (hash && msisdn) memCache.set(String(hash).toLowerCase(), msisdn);
  }

  module.exports = { looksHashed, decodeHash, primeCache, SAF_PREFIXES };

} else {
  // Worker Thread context - performs brute forcing
  const hash = workerData.hash;

  // Pre-generate padded strings (000000 - 999999) to bypass padStart overhead
  const padded = [];
  for (let i = 0; i < 1_000_000; i++) {
    padded.push(String(i).padStart(6, '0'));
  }

  // Optimized hash utility using native crypto.hash if available
  const hasCryptoHash = typeof crypto.hash === 'function';
  function sha256hex(s) {
    if (hasCryptoHash) {
      return crypto.hash('sha256', s, 'hex');
    }
    return crypto.createHash('sha256').update(s).digest('hex');
  }

  let found = null;
  outer:
  for (const pre of SAF_PREFIXES) {
    for (let n = 0; n < 1_000_000; n++) {
      const msisdn = '254' + pre + padded[n];
      if (sha256hex(msisdn) === hash) {
        found = msisdn;
        break outer;
      }
    }
  }

  parentPort.postMessage(found);
  process.exit(0);
}
