const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  
  const hash = crypto.pbkdf2Sync(
    password,
    salt,
    100000,
    64,
    'sha512'
  );
  
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, hashedPassword) {
  const [salt, storedHash] = hashedPassword.split(':');
  
  const saltBuffer = Buffer.from(salt, 'hex');
  
  const hash = crypto.pbkdf2Sync(
    password,
    saltBuffer,
    100000,
    64,
    'sha512'
  );
  
  const hashesMatch = hash.toString('hex') === storedHash;
  return hashesMatch ? true : false;
}

module.exports = {
  hashPassword,
  verifyPassword
}; 