var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "crypto-js", "crypto-js/lib-typedarrays", "pako"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.decrypt = exports.encrypt = exports.getFilename = exports.sha1 = void 0;
    const crypto_js_1 = __importDefault(require("crypto-js"));
    require("crypto-js/lib-typedarrays");
    const pako_1 = __importDefault(require("pako"));
    const JsonFormatter = {
        stringify: (cipherParams) => {
            const jsonObj = {
                ct: cipherParams.ciphertext.toString(crypto_js_1.default.enc.Base64),
                iv: cipherParams.iv && cipherParams.iv.toString() || undefined,
                sa: cipherParams.salt && cipherParams.salt.toString() || undefined,
            };
            return JSON.stringify(jsonObj);
        },
        parse: (jsonStr) => {
            const jsonObj = JSON.parse(jsonStr);
            const cipherParams = crypto_js_1.default.lib.CipherParams.create({
                ciphertext: crypto_js_1.default.enc.Base64.parse(jsonObj.ct)
            });
            if (jsonObj.iv) {
                cipherParams.iv = crypto_js_1.default.enc.Hex.parse(jsonObj.iv);
            }
            if (jsonObj.sa) {
                cipherParams.salt = crypto_js_1.default.enc.Hex.parse(jsonObj.sa);
            }
            return cipherParams;
        }
    };
    function sha1(contents) {
        if (typeof contents === 'string') {
            return crypto_js_1.default.enc.Hex.stringify(crypto_js_1.default.SHA1(contents));
        }
        // const wordArray = CryptoJS.lib.WordArray.create();
        // const chunkSize = 1024;
        // for (let byte = 0; byte < contents.length; byte += chunkSize) {
        //   const chunk = contents.slice(byte, byte + chunkSize);
        //   const chunkAry = [...(new Uint32Array(chunk.buffer))];
        //   wordArray.concat(CryptoJS.lib.WordArray.create(chunkAry, chunk.length));
        // }
        return crypto_js_1.default.enc.Hex.stringify(crypto_js_1.default.SHA1(crypto_js_1.default.lib.WordArray.create(contents)));
    }
    exports.sha1 = sha1;
    const getFilename = (hash, fileIndex) => sha1(`${hash}_${fileIndex}`);
    exports.getFilename = getFilename;
    function encrypt(uint8array, secret) {
        const srcString = uint8array.reduce((str, code) => str + String.fromCharCode(code), '');
        const encrypted = crypto_js_1.default.AES.encrypt(crypto_js_1.default.enc.Latin1.parse(srcString), secret, {
            format: JsonFormatter
        });
        return pako_1.default.deflate(encrypted.toString());
    }
    exports.encrypt = encrypt;
    function decrypt(encrypted, secret) {
        const uint8ary = pako_1.default.inflate(encrypted);
        const decrypted = crypto_js_1.default.AES.decrypt(new TextDecoder().decode(uint8ary), secret, {
            format: JsonFormatter
        }).toString(crypto_js_1.default.enc.Latin1);
        return Uint8Array.from(Buffer.from(decrypted, 'latin1'));
    }
    exports.decrypt = decrypt;
});
//# sourceMappingURL=crypto.js.map