import 'crypto-js/lib-typedarrays';
export declare function sha1(contents: any | string): string;
export declare const getFilename: (hash: string, fileIndex: number | string, secret: string) => string;
export declare function encrypt(uint8array: Uint8Array, secret: string): Uint8Array;
export declare function decrypt(encrypted: Uint8Array, secret: string): Uint8Array;
//# sourceMappingURL=crypto.d.ts.map