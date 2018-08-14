const crypto = require('crypto');
const ALGORITHM = 'aes192';
const KEY = 'x82m#*lx8';
/**
 * @param {Buffer} buf
 * @param {String} key
 * @param {String} algorithm
 * @returns {String}
 */
function cipher(buf, key = KEY, algorithm = ALGORITHM) {
  if (!(buf instanceof Buffer)) {
    buf = new Buffer(buf);
  }
  var encrypted = '';
  var cip = crypto.createCipher(algorithm, key);
  encrypted += cip.update(buf, 'utf8', 'hex');
  encrypted += cip.final('hex');
  return encrypted;
};
/**
 * @param {String} encrypted
 * @param {String} key
 * @param {String} algorithm
 * @returns {String}
 */
function decipher(encrypted, key = KEY, algorithm = ALGORITHM) {
  var decrypted = '';
  var decipher = crypto.createDecipher(algorithm, key);
  decrypted += decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
`;
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
`;
const encryptPublickey = { key: PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_PADDING };
const decryptPrivatekey = { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_PADDING };
/**
 * @returns {Buffer}
 */
const publicEncrypt = crypto.publicEncrypt;

/**
 * @returns {Buffer}
 */
const privateDecrypt = crypto.privateDecrypt;
/**
 * usage:
 * const password='123456'  ;
 * const encoded = publicEncrypt(encryptPublickey, new Buffer(password));
 * console.log(encoded.toString('hex'));
 * privateDecrypt(privateDecrypt, encoded).toString('utf8') === password;
 */
export default {
  aes: {
    cipher: cipher,
    decipher: decipher
  },
  rsa: {
    encryptPublickey,
    decryptPrivatekey,
    publicEncrypt,
    privateDecrypt
  }
};
