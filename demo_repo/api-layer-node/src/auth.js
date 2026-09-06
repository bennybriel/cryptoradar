const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Modern API-layer auth service (fronts the legacy core over a REST facade).
function issueToken(payload, privateKey) {
  // RS256 chosen originally for interop with partner banks' JWKS validators.
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '15m' });
}

function legacyChecksum(body) {
  // Kept for backward compatibility with an older mobile app version.
  return crypto.createHash('sha1').update(body).digest('hex');
}

function encryptSessionBlob(data, key) {
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

const CONFIG_SECRET = "hardcoded_demo_secret_do_not_ship_9f8a7b6c5d4e3f2a1b0c9d8e";

module.exports = { issueToken, legacyChecksum, encryptSessionBlob };
