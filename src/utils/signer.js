import forge from 'node-forge';
import moment from 'moment';
import jwt from 'jsonwebtoken';
import uuid from 'uuid/v4';
import LittleEndian from "int64-buffer";
import crypto from 'crypto';
import nacl from "tweetnacl";

function Signer() {
}

Signer.prototype = {
  signAuthenticationToken: function(uid, sid, method, uri, body) {
    if (typeof(body) === "object") {
      body = JSON.stringify(body);
    }

    let expire = moment.utc().add(30, 'minutes').unix();
    let sha256 = forge.md.sha256.create();
    sha256.update(method + uri + body);
    let payload = {
      uid: uid,
      sid: sid,
      iat: moment.utc().unix(),
      exp: expire,
      jti: uuid(),
      sig: sha256.digest().toHex()
    };
    const keyPair = crypto.createECDH('secp256k1');
    keyPair.generateKeys();
    let pem = `-----BEGIN PRIVATE KEY-----
${Buffer.from(`308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420${keyPair.getPrivateKey('hex')}a144034200${keyPair.getPublicKey('hex')}`, 'hex').toString('base64')}
-----END PRIVATE KEY-----`
    return jwt.sign(payload, pem, { algorithm: 'ES256'});
  },

  signEncryptedPin: function(pin, pinToken, sessionId, privateKey, iterator) {
    const blockSize = 16;
    let Uint64LE = LittleEndian.Int64BE;

    let pub = Uint8Array.from(new Buffer(pinToken, 'base64'));
    let priv = Uint8Array.from(Buffer.from(privateKey, 'hex'));
    let key = Buffer.from(nacl.scalarMult(priv, pub)).toString('hex');
    let time = new Uint64LE(moment.utc().unix());
    time = [...time.toBuffer()].reverse();
    if (iterator == undefined || iterator === "") {
      iterator = Date.now() * 1000000;
    }
    iterator = new Uint64LE(iterator);
    iterator = [...iterator.toBuffer()].reverse();
    pin = Buffer.from(pin, 'utf8');
    let buf = Buffer.concat([pin, Buffer.from(time), Buffer.from(iterator)]);
    let padding = blockSize - buf.length % blockSize;
    let paddingArray = [];
    for (let i=0; i<padding; i++) {
      paddingArray.push(padding);
    };

    buf = Buffer.concat([buf, new Buffer(paddingArray)]);
    let iv16  = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv16);
    cipher.setAutoPadding(false);
    let encrypted_pin_buff = cipher.update(buf, 'utf-8');
    encrypted_pin_buff = Buffer.concat([iv16 , encrypted_pin_buff]);
    return Buffer.from(encrypted_pin_buff).toString('base64');
  },

  hexToBytes: function (hex) {
    var bytes = [];
    for (let c=0; c<hex.length; c+=2) {
      bytes.push(parseInt(hex.substr(c, 2), 16));
    };
    return bytes;
  },
};

export default Signer;
