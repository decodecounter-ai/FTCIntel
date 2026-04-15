// FTCIntel Security Utilities — load AFTER config.js (requires APP_KEY)

/**
 * Strip characters that could cause XSS or injection when user input is
 * reflected back into HTML or URL parameters.
 */
function sanitizeInput(val, maxLen) {
  maxLen = maxLen || 200;
  if (!val && val !== 0) return '';
  return val.toString().replace(/[<>"'`\\]/g, '').trim().substring(0, maxLen);
}

/**
 * HTML-encode a string before inserting it into innerHTML.
 * Use this on all server-returned data rendered via innerHTML.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * SHA-256 hash via Web Crypto API. Returns a lowercase hex string.
 */
async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Add appKey, a timestamp, and a request signature to a params object.
 * The signature covers all params (sorted alphabetically) + APP_KEY.
 * Returns a new object with appKey, ts, and sig added.
 */
async function buildSignedParams(params) {
  const signed = Object.assign({}, params, {
    appKey: APP_KEY,
    ts: Date.now().toString()
  });
  const canonical = Object.keys(signed)
    .filter(k => k !== 'sig')
    .sort()
    .map(k => k + '=' + signed[k])
    .join('&');
  signed.sig = await sha256(canonical + APP_KEY);
  return signed;
}
