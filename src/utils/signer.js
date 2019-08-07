import forge from 'node-forge';
import moment from 'moment';
import uuid from 'uuid/v4';
import LittleEndian from "int64-buffer";

function Signer() {
  signAuthenticationToken: function(uid, sid, privateKey, method, uri, body) {
    if (typeof(body) === "object") {
      body = JSON.stringify(body);
    }

    let expire = moment.utc().add(30, 'minutes').unix();
    let sha256 = forge.md.sha256.create();
    sha256.update(method + uri + body);
    let payload = {
      uid: uid,
      sid: sid,
      iat: moment.utc().unix() ,
      exp: expire,
      jti: uuid(),
      sig: sha256.digest().toHex()
    };
    let seed = Uint8Array.from(Buffer.from(privateKey, 'hex'));
    let keypair = forge.pki.ed25519.generateKeyPair({seed: seed});
    return jwt.sign(payload, keypair.privateKey, { algorithm: 'ES256'});
  },

  signEncryptedPin: function (pin, pinToken, sessionId, privateKey, iterator) {
    const blockSize = 16;
    let Uint64LE = LittleEndian.Int64BE;

    public = Uint8Array.from(new Buffer(pinToken, 'base64'));
    private = Uint8Array.from(Buffer.from(privateKey, 'hex'));
    key = Buffer.from(nacl.scalarMult(asa, abp)).toString('hex');
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
    let cipher = crypto.createCipheriv('aes-256-cbc', this.hexToBytes(key), iv16);
    cipher.setAutoPadding(false);
    let encrypted_pin_buff = cipher.update(buf, 'utf-8');
    encrypted_pin_buff = Buffer.concat([iv16 , encrypted_pin_buff]);
    return Buffer.from(encrypted_pin_buff).toString('base64');
  },

  hexToBytes: function (hex) {
    var bytes = [];
    for (let c=0; c<hex.length; c+=2) {
      bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
  }
};

export default Signer;
