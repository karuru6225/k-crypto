import CryptoJS from 'crypto-js';
import pako from 'pako';

const JsonFormatter = {
  stringify: (cipherParams: CryptoJS.lib.CipherParams) => {
    const jsonObj = {
      ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64),
      iv: cipherParams.iv && cipherParams.iv.toString() || undefined,
      sa: cipherParams.salt && cipherParams.salt.toString() || undefined,
    };
    return JSON.stringify(jsonObj);
  },
  parse: (jsonStr: string) => {
    const jsonObj = JSON.parse(jsonStr);
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(jsonObj.ct)
    });
    if (jsonObj.iv) {
      cipherParams.iv = CryptoJS.enc.Hex.parse(jsonObj.iv);
    }
    if (jsonObj.sa) {
      cipherParams.salt = CryptoJS.enc.Hex.parse(jsonObj.sa);
    }
    return cipherParams;
  }
};

export function sha1(contents: Uint8Array | string): string {
  if (typeof contents === 'string') {
    return CryptoJS.enc.Hex.stringify(CryptoJS.SHA1(contents));
  }

  const wordArray = CryptoJS.lib.WordArray.create();
  const chunkSize = 1024;
  for (let byte = 0; byte < contents.length; byte += chunkSize) {
    const chunk = contents.slice(byte, byte + chunkSize);
    const chunkAry = [...(new Uint32Array(chunk.buffer))];
    wordArray.concat(CryptoJS.lib.WordArray.create(chunkAry, chunk.length));
  }
  return CryptoJS.enc.Hex.stringify(CryptoJS.SHA1(wordArray));
}

export const getFilename = (hash: string, fileIndex: number | string): string =>
  sha1(`${hash}_${fileIndex}`);

export function encrypt(uint8array: Uint8Array, secret: string): Uint8Array {
  const srcString = uint8array.reduce((str, code) => str + String.fromCharCode(code), '');
  const encrypted = CryptoJS.AES.encrypt(
    CryptoJS.enc.Latin1.parse(srcString),
    secret,
    {
      format: JsonFormatter
    }
  );
  return pako.deflate(encrypted.toString());
}

export function decrypt(encrypted: Uint8Array, secret: string): Uint8Array {
  const uint8ary = pako.inflate(encrypted)
  const decrypted = CryptoJS.AES.decrypt(
    new TextDecoder().decode(uint8ary),
    secret,
    {
      format: JsonFormatter
    }
  ).toString(CryptoJS.enc.Latin1);
  return Uint8Array.from(Buffer.from(decrypted, 'latin1'));
}
