const crypto = require('crypto');

function base64urlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const now = Math.floor(Date.now() / 1000);
  const payloadWithExp = {
    ...payload,
    exp: now + expiresInSeconds
  };

  const encodedHeader = base64urlEncode(Buffer.from(JSON.stringify(header)));
  const encodedPayload = base64urlEncode(Buffer.from(JSON.stringify(payloadWithExp)));

  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(signatureInput)
    .digest();

  return `${signatureInput}.${base64urlEncode(signature)}`;
}

function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signatureInput)
    .digest();

  const actualSignature = Buffer.from(encodedSignature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  if (!crypto.timingSafeEqual(expectedSignature, actualSignature)) {
    throw new Error('Invalid signature');
  }

  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && payload.exp < now) {
    throw new Error('Token expired');
  }

  return payload;
}

module.exports = {
  signJWT,
  verifyJWT
};
