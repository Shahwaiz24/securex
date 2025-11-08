/**
 * Unified Crypto Core - Pure JavaScript Implementation
 * Zero dependencies, cross-platform mathematical encryption
 */

import { shouldShowSecurityWarning, markSecurityWarningAsShown } from './global-state.js';

interface EncryptedFormat {
    v: string;
    i: string;
    d: string;
    t: string;
}

class MathBase64 {
    private static readonly CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    static encode(bytes: Uint8Array): string {
        let result = '';
        for (let i = 0; i < bytes.length; i += 3) {
            const a = bytes[i];
            const b = bytes[i + 1] || 0;
            const c = bytes[i + 2] || 0;
            const bitmap = (a << 16) | (b << 8) | c;

            result += this.CHARS[(bitmap >> 18) & 63];
            result += this.CHARS[(bitmap >> 12) & 63];
            if (i + 1 < bytes.length) result += this.CHARS[(bitmap >> 6) & 63];
            if (i + 2 < bytes.length) result += this.CHARS[bitmap & 63];
        }
        return result;
    }

    static decode(str: string): Uint8Array {
        const len = str.length;
        const bytes = new Uint8Array((len * 3) >> 2);
        let p = 0;

        for (let i = 0; i < len; i += 4) {
            const a = this.CHARS.indexOf(str[i]);
            const b = this.CHARS.indexOf(str[i + 1]);
            const c = this.CHARS.indexOf(str[i + 2]);
            const d = this.CHARS.indexOf(str[i + 3]);

            const bitmap = (a << 18) | (b << 12) | (c << 6) | d;
            bytes[p++] = (bitmap >> 16) & 255;
            if (c !== -1) bytes[p++] = (bitmap >> 8) & 255;
            if (d !== -1) bytes[p++] = bitmap & 255;
        }
        return bytes.slice(0, p);
    }
}

class MemoryPool {
    private static pools = new Map<number, Uint8Array[]>();
    private static maxPoolSize = 50;

    static getBuffer(size: number): Uint8Array {
        const pool = this.pools.get(size);
        if (pool && pool.length > 0) {
            return pool.pop()!;
        }
        return new Uint8Array(size);
    }

    static returnBuffer(buffer: Uint8Array): void {
        const size = buffer.length;
        if (!this.pools.has(size)) {
            this.pools.set(size, []);
        }

        const pool = this.pools.get(size)!;
        if (pool.length < this.maxPoolSize) {
            buffer.fill(0);
            pool.push(buffer);
        }
    }

    static cleanup(): void {
        this.pools.clear();
    }
}

class OptimizedRandom {
    private static seed = Date.now() ^ (Math.random() * 0x100000000);
    private static buffer = new Uint8Array(1024);
    private static bufferPos = 1024;

    static generateBytes(length: number): Uint8Array {
        const result = MemoryPool.getBuffer(length);

        for (let i = 0; i < length; i++) {
            if (this.bufferPos >= 1024) {
                this.fillBuffer();
                this.bufferPos = 0;
            }
            result[i] = this.buffer[this.bufferPos++];
        }

        return result;
    }

    private static fillBuffer(): void {
        for (let i = 0; i < 1024; i++) {
            this.seed = (this.seed * 1664525 + 1013904223) >>> 0;
            this.buffer[i] = (this.seed >>> 24) ^ (this.seed >>> 16) ^ (this.seed >>> 8) ^ this.seed;
        }
    }

    static generateHex(length: number): string {
        const bytes = this.generateBytes(length);
        let result = '';
        for (let i = 0; i < length; i++) {
            result += bytes[i].toString(16).padStart(2, '0');
        }
        MemoryPool.returnBuffer(bytes);
        return result;
    }
}

class OptimizedAES {
    private static readonly SBOX = new Uint8Array([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]);

    private static readonly RCON = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

    private static readonly MUL2 = new Uint8Array(256);
    private static readonly MUL3 = new Uint8Array(256);
    private static initialized = false;

    private static init(): void {
        if (this.initialized) return;

        for (let i = 0; i < 256; i++) {
            this.MUL2[i] = (i << 1) ^ (i & 0x80 ? 0x1b : 0);
            this.MUL3[i] = this.MUL2[i] ^ i;
        }
        this.initialized = true;
    }

    static expandKey(key: Uint8Array): Uint8Array {
        this.init();
        const expanded = MemoryPool.getBuffer(240);
        expanded.set(key);

        for (let i = 32; i < 240; i += 4) {
            const prev = i - 4;
            let t0 = expanded[prev], t1 = expanded[prev + 1], t2 = expanded[prev + 2], t3 = expanded[prev + 3];

            if (i % 32 === 0) {
                const temp = t0;
                t0 = this.SBOX[t1] ^ this.RCON[(i / 32) - 1];
                t1 = this.SBOX[t2];
                t2 = this.SBOX[t3];
                t3 = this.SBOX[temp];
            } else if (i % 32 === 16) {
                t0 = this.SBOX[t0];
                t1 = this.SBOX[t1];
                t2 = this.SBOX[t2];
                t3 = this.SBOX[t3];
            }

            expanded[i] = expanded[i - 32] ^ t0;
            expanded[i + 1] = expanded[i - 31] ^ t1;
            expanded[i + 2] = expanded[i - 30] ^ t2;
            expanded[i + 3] = expanded[i - 29] ^ t3;
        }
        return expanded;
    }

    static encryptBlock(block: Uint8Array, expandedKey: Uint8Array): Uint8Array {
        const state = MemoryPool.getBuffer(16);
        state.set(block);

        let keyOffset = 0;
        for (let i = 0; i < 16; i++) {
            state[i] ^= expandedKey[keyOffset++];
        }

        for (let round = 1; round < 14; round++) {
            for (let i = 0; i < 16; i++) {
                state[i] = this.SBOX[state[i]];
            }

            const temp = new Uint8Array(state);
            state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
            state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
            state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];

            for (let c = 0; c < 4; c++) {
                const s0 = state[c * 4], s1 = state[c * 4 + 1], s2 = state[c * 4 + 2], s3 = state[c * 4 + 3];
                state[c * 4] = this.MUL2[s0] ^ this.MUL3[s1] ^ s2 ^ s3;
                state[c * 4 + 1] = s0 ^ this.MUL2[s1] ^ this.MUL3[s2] ^ s3;
                state[c * 4 + 2] = s0 ^ s1 ^ this.MUL2[s2] ^ this.MUL3[s3];
                state[c * 4 + 3] = this.MUL3[s0] ^ s1 ^ s2 ^ this.MUL2[s3];
            }

            for (let i = 0; i < 16; i++) {
                state[i] ^= expandedKey[keyOffset++];
            }
        }

        for (let i = 0; i < 16; i++) {
            state[i] = this.SBOX[state[i]];
        }

        const temp = new Uint8Array(state);
        state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
        state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];

        for (let i = 0; i < 16; i++) {
            state[i] ^= expandedKey[keyOffset++];
        }

        return state;
    }

}
class OptimizedGCM {
    static encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): { encrypted: Uint8Array; tag: Uint8Array } {
        const expandedKey = OptimizedAES.expandKey(key);
        const zeroBlock = MemoryPool.getBuffer(16);
        zeroBlock.fill(0);
        const h = OptimizedAES.encryptBlock(zeroBlock, expandedKey);
        MemoryPool.returnBuffer(zeroBlock);

        // Initialize counter: J0 = IV || 0^31 || 1, then use J0+1, J0+2, etc. for encryption
        const counter = MemoryPool.getBuffer(16);
        counter.fill(0); // Initialize to zeros first
        counter.set(iv, 0); // First 12 bytes = IV
        // Bytes 12-14 are already 0 from fill(0)
        counter[15] = 2; // Start at J0+1 = IV || 0 || 0 || 0 || 2 (first block uses counter 2)

        const encrypted = MemoryPool.getBuffer(data.length);
        for (let i = 0; i < data.length; i += 16) {
            const keystream = OptimizedAES.encryptBlock(counter, expandedKey);
            const blockSize = Math.min(16, data.length - i);

            for (let j = 0; j < blockSize; j++) {
                encrypted[i + j] = data[i + j] ^ keystream[j];
            }
            MemoryPool.returnBuffer(keystream);

            this.incrementCounter(counter);
        }

        const tag = this.ghash(h, new Uint8Array(0), encrypted);

        // Finalize tag with J0 encryption (J0 = IV || 0^31 || 1 for 96-bit IV)
        const j0 = MemoryPool.getBuffer(16);
        j0.fill(0); // Initialize to zeros first
        j0.set(iv, 0); // First 12 bytes = IV
        // Bytes 12-14 are already 0 from fill(0)
        j0[15] = 1; // Last byte = 1 (J0 for 96-bit IV)
        const tagBlock = OptimizedAES.encryptBlock(j0, expandedKey);
        for (let i = 0; i < 16; i++) {
            tag[i] ^= tagBlock[i];
        }
        MemoryPool.returnBuffer(tagBlock);
        MemoryPool.returnBuffer(j0);
        MemoryPool.returnBuffer(counter);
        MemoryPool.returnBuffer(expandedKey);
        MemoryPool.returnBuffer(h);

        return { encrypted, tag };
    }

    static decrypt(encrypted: Uint8Array, key: Uint8Array, iv: Uint8Array, expectedTag: Uint8Array): Uint8Array {
        const expandedKey = OptimizedAES.expandKey(key);
        const zeroBlock = MemoryPool.getBuffer(16);
        zeroBlock.fill(0);
        const h = OptimizedAES.encryptBlock(zeroBlock, expandedKey);
        MemoryPool.returnBuffer(zeroBlock);

        // Verify tag first before decrypting
        const computedTag = this.ghash(h, new Uint8Array(0), encrypted);

        // Use J0 (J0 = IV || 0^31 || 1 for 96-bit IV) for tag encryption
        const j0 = MemoryPool.getBuffer(16);
        j0.fill(0); // Initialize to zeros first
        j0.set(iv, 0); // First 12 bytes = IV
        // Bytes 12-14 are already 0 from fill(0)
        j0[15] = 1; // Last byte = 1 (J0 for 96-bit IV)
        const tagBlock = OptimizedAES.encryptBlock(j0, expandedKey);
        for (let i = 0; i < 16; i++) {
            computedTag[i] ^= tagBlock[i];
        }
        MemoryPool.returnBuffer(tagBlock);
        MemoryPool.returnBuffer(j0);

        // Constant-time tag comparison
        let tagMatch = 0;
        for (let i = 0; i < 16; i++) {
            tagMatch |= computedTag[i] ^ expectedTag[i];
        }

        MemoryPool.returnBuffer(expandedKey);
        MemoryPool.returnBuffer(h);
        MemoryPool.returnBuffer(computedTag);

        if (tagMatch !== 0) {
            throw new Error("Authentication failed");
        }

        // Decrypt data (use same counter sequence as encryption: J0+1, J0+2, etc.)
        const counter = MemoryPool.getBuffer(16);
        counter.fill(0); // Initialize to zeros first
        counter.set(iv, 0); // First 12 bytes = IV
        // Bytes 12-14 are already 0 from fill(0)
        counter[15] = 2; // Start at J0+1 = IV || 0 || 0 || 0 || 2 (first block uses counter 2)

        const decrypted = MemoryPool.getBuffer(encrypted.length);
        for (let i = 0; i < encrypted.length; i += 16) {
            const keystream = OptimizedAES.encryptBlock(counter, expandedKey);
            const blockSize = Math.min(16, encrypted.length - i);

            for (let j = 0; j < blockSize; j++) {
                decrypted[i + j] = encrypted[i + j] ^ keystream[j];
            }
            MemoryPool.returnBuffer(keystream);

            this.incrementCounter(counter);
        }

        MemoryPool.returnBuffer(counter);
        MemoryPool.returnBuffer(expandedKey);

        return decrypted;
    }

    private static incrementCounter(counter: Uint8Array): void {
        for (let i = 15; i >= 12; i--) {
            if (++counter[i] !== 0) break;
        }
    }

    private static ghash(h: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        let x = new Uint8Array(16);
        x.fill(0); // Initialize to zero

        // Process AAD (Additional Authenticated Data) first
        for (let i = 0; i < aad.length; i += 16) {
            const block = new Uint8Array(16);
            block.fill(0); // Initialize to zero for padding

            const aadSlice = aad.slice(i, i + 16);
            block.set(aadSlice, 0); // Copy AAD data (remaining bytes stay 0 for padding)

            // XOR with current x
            for (let j = 0; j < 16; j++) {
                x[j] ^= block[j];
            }

            // Multiply by h
            const result = this.gfMul128(x, h);
            x = new Uint8Array(result);
        }

        // Process ciphertext blocks
        for (let i = 0; i < ciphertext.length; i += 16) {
            const block = new Uint8Array(16);
            block.fill(0); // Initialize to zero for padding

            const ctSlice = ciphertext.slice(i, i + 16);
            block.set(ctSlice, 0); // Copy ciphertext data (remaining bytes stay 0 for padding)

            // XOR with current x
            for (let j = 0; j < 16; j++) {
                x[j] ^= block[j];
            }

            // Multiply by h
            const result = this.gfMul128(x, h);
            x = new Uint8Array(result);
        }

        // Append length block: 64 bits AAD length || 64 bits ciphertext length
        // According to GCM spec: first 64 bits = AAD length, last 64 bits = ciphertext length
        const lenBlock = new Uint8Array(16);
        lenBlock.fill(0); // Initialize to zero

        const aadBits = aad.length * 8;
        const ctBits = ciphertext.length * 8;

        // AAD length (64 bits) - bytes 0-7 (big-endian, but only lower 32 bits used typically)
        // For most cases, AAD is 0, so bytes 0-7 will be 0
        lenBlock[4] = (aadBits >>> 24) & 0xff;
        lenBlock[5] = (aadBits >>> 16) & 0xff;
        lenBlock[6] = (aadBits >>> 8) & 0xff;
        lenBlock[7] = aadBits & 0xff;

        // Ciphertext length (64 bits) - bytes 8-15 (big-endian, but only lower 32 bits used typically)
        lenBlock[12] = (ctBits >>> 24) & 0xff;
        lenBlock[13] = (ctBits >>> 16) & 0xff;
        lenBlock[14] = (ctBits >>> 8) & 0xff;
        lenBlock[15] = ctBits & 0xff;

        // XOR length block with x
        for (let j = 0; j < 16; j++) {
            x[j] ^= lenBlock[j];
        }

        // Final multiplication by h
        const result = this.gfMul128(x, h);
        return new Uint8Array(result);
    }

    private static gfMul128(x: Uint8Array, y: Uint8Array): any {
        const z = new Uint8Array(16);
        const v = new Uint8Array(y);

        for (let i = 0; i < 128; i++) {
            if (x[Math.floor(i / 8)] & (0x80 >>> (i % 8))) {
                for (let j = 0; j < 16; j++) {
                    z[j] ^= v[j];
                }
            }

            const lsb = v[15] & 1;
            for (let j = 15; j > 0; j--) {
                v[j] = (v[j] >>> 1) | ((v[j - 1] & 1) << 7);
            }
            v[0] >>>= 1;

            if (lsb) {
                v[0] ^= 0xe1;
            }
        }

        return z;
    }
}

class OptimizedCryptoEngine {
    private readonly KEY_LENGTH = 32;
    private readonly IV_LENGTH = 12;
    private readonly TAG_LENGTH = 16;
    private readonly VERSION = '2.0';

    private expandedKeyCache = new Map<string, {
        expanded: Uint8Array;
        h: Uint8Array;
        lastUsed: number;
    }>();
    private readonly MAX_CACHE_SIZE = 100;
    private readonly CACHE_TTL = 300000;
    private currentSecretKey = '';

    private getExpandedKey(secretKey: string): { expanded: Uint8Array; h: Uint8Array } {
        if (!secretKey || typeof secretKey !== 'string' || secretKey.length !== 64 || !/^[0-9a-f]+$/i.test(secretKey)) {
            throw new Error("Invalid secret key format");
        }

        const now = Date.now();
        const cached = this.expandedKeyCache.get(secretKey);

        if (cached && (now - cached.lastUsed) < this.CACHE_TTL) {
            cached.lastUsed = now;
            return { expanded: cached.expanded, h: cached.h };
        }

        if (shouldShowSecurityWarning()) {
            console.warn("🔐 SECUREX V2.0 - Optimized crypto active");
            markSecurityWarningAsShown();
        }

        const keyBytes = MemoryPool.getBuffer(this.KEY_LENGTH);
        for (let i = 0; i < this.KEY_LENGTH; i++) {
            keyBytes[i] = parseInt(secretKey.substr(i * 2, 2), 16);
        }

        const expanded = OptimizedAES.expandKey(keyBytes);
        const zeroBlock = MemoryPool.getBuffer(16);
        zeroBlock.fill(0);
        const h = OptimizedAES.encryptBlock(zeroBlock, expanded);

        MemoryPool.returnBuffer(keyBytes);
        MemoryPool.returnBuffer(zeroBlock);

        this.cleanupCache();

        this.expandedKeyCache.set(secretKey, {
            expanded: new Uint8Array(expanded),
            h: new Uint8Array(h),
            lastUsed: now
        });

        return { expanded, h };
    }

    private cleanupCache(): void {
        if (this.expandedKeyCache.size >= this.MAX_CACHE_SIZE) {
            const now = Date.now();
            const toDelete: string[] = [];

            for (const [key, value] of this.expandedKeyCache) {
                if (now - value.lastUsed > this.CACHE_TTL) {
                    toDelete.push(key);
                }
            }

            toDelete.forEach(key => this.expandedKeyCache.delete(key));

            if (this.expandedKeyCache.size >= this.MAX_CACHE_SIZE) {
                const entries = Array.from(this.expandedKeyCache.entries());
                entries.sort((a, b) => a[1].lastUsed - b[1].lastUsed);
                const toRemove = entries.slice(0, Math.floor(this.MAX_CACHE_SIZE / 2));
                toRemove.forEach(([key]) => this.expandedKeyCache.delete(key));
            }
        }
    }

    async generateSecretKey(): Promise<string> {
        return OptimizedRandom.generateHex(this.KEY_LENGTH);
    }

    async encrypt(data: string, secretKey: string): Promise<string> {
        if (!data || typeof data !== "string") {
            throw new Error("Invalid data");
        }

        if (shouldShowSecurityWarning()) {
            console.warn("🔐 SECUREX V2.0 - Unified AES-GCM crypto active");
            markSecurityWarningAsShown();
        }

        // Parse key and generate IV
        const keyBytes = this.parseSecretKey(secretKey);
        const iv = OptimizedRandom.generateBytes(this.IV_LENGTH);
        const dataBytes = new TextEncoder().encode(data);

        // Use proper AES-GCM encryption (works identically in browser and Node.js)
        const { encrypted, tag } = OptimizedGCM.encrypt(dataBytes, keyBytes, iv);

        const result: EncryptedFormat = {
            v: this.VERSION,
            i: MathBase64.encode(iv),
            d: MathBase64.encode(encrypted),
            t: MathBase64.encode(tag)
        };

        MemoryPool.returnBuffer(keyBytes);
        MemoryPool.returnBuffer(iv);

        return JSON.stringify(result);
    }

    async decrypt(encryptedData: string, secretKey: string): Promise<string> {
        if (!encryptedData || typeof encryptedData !== "string") {
            throw new Error("Invalid encrypted data");
        }

        let parsed: EncryptedFormat;
        try {
            parsed = JSON.parse(encryptedData);
        } catch {
            throw new Error("Invalid data format");
        }

        if (!parsed.v || !parsed.i || !parsed.d || !parsed.t) {
            throw new Error("Missing required fields");
        }

        const keyBytes = this.parseSecretKey(secretKey);
        const iv = MathBase64.decode(parsed.i);
        const encrypted = MathBase64.decode(parsed.d);
        const expectedTag = MathBase64.decode(parsed.t);

        // Use proper AES-GCM decryption with tag verification (works identically in browser and Node.js)
        try {
            const decrypted = this.decryptGCM(encrypted, keyBytes, iv, expectedTag);
            const result = new TextDecoder().decode(decrypted);

            MemoryPool.returnBuffer(keyBytes);
            MemoryPool.returnBuffer(decrypted);

            return result;
        } catch (error) {
            MemoryPool.returnBuffer(keyBytes);
            if (error instanceof Error && error.message.includes("Authentication failed")) {
                throw error;
            }
            throw new Error("Decryption failed");
        }
    }

    private parseSecretKey(secretKey: string): Uint8Array {
        if (!secretKey || typeof secretKey !== 'string' || secretKey.length !== 64 || !/^[0-9a-f]+$/i.test(secretKey)) {
            throw new Error("Invalid secret key format");
        }

        const keyBytes = MemoryPool.getBuffer(this.KEY_LENGTH);
        for (let i = 0; i < this.KEY_LENGTH; i++) {
            keyBytes[i] = parseInt(secretKey.substr(i * 2, 2), 16);
        }
        return keyBytes;
    }

    private decryptGCM(encrypted: Uint8Array, key: Uint8Array, iv: Uint8Array, expectedTag: Uint8Array): Uint8Array {
        // Use OptimizedGCM.decrypt which properly verifies tag before decrypting
        return OptimizedGCM.decrypt(encrypted, key, iv, expectedTag);
    }

    private incrementCounter(counter: Uint8Array): void {
        for (let i = 15; i >= 12; i--) {
            if (++counter[i] !== 0) break;
        }
    }

    private computeGHASH(h: Uint8Array, ciphertext: Uint8Array, iv: Uint8Array): Uint8Array {
        // Simple approach: use the working GCM from OptimizedGCM
        const { expanded } = this.getExpandedKey(this.currentSecretKey);

        // Create key bytes for compatibility
        const keyBytes = MemoryPool.getBuffer(32);
        for (let i = 0; i < 32; i++) {
            keyBytes[i] = parseInt(this.currentSecretKey.substr(i * 2, 2), 16);
        }

        // Use the working GCM implementation
        const result = OptimizedGCM.encrypt(ciphertext, keyBytes, iv);

        MemoryPool.returnBuffer(keyBytes);

        return result.tag;
    }

    private gfMul128(x: Uint8Array, y: Uint8Array): Uint8Array {
        const z = MemoryPool.getBuffer(16);
        const v = MemoryPool.getBuffer(16);
        z.fill(0);
        v.set(y);

        for (let i = 0; i < 128; i++) {
            if (x[Math.floor(i / 8)] & (0x80 >>> (i % 8))) {
                for (let j = 0; j < 16; j++) {
                    z[j] ^= v[j];
                }
            }

            const lsb = v[15] & 1;
            for (let j = 15; j > 0; j--) {
                v[j] = (v[j] >>> 1) | ((v[j - 1] & 1) << 7);
            }
            v[0] >>>= 1;

            if (lsb) {
                v[0] ^= 0xe1;
            }
        }

        MemoryPool.returnBuffer(v);
        return z;
    }

    cleanup(): void {
        this.expandedKeyCache.clear();
        MemoryPool.cleanup();
    }
}

export const unifiedCrypto = new OptimizedCryptoEngine();

export {
    OptimizedCryptoEngine as UnifiedCryptoEngine,
    MathBase64,
    OptimizedRandom as MathRandom,
    OptimizedAES as MathAES,
    OptimizedGCM as MathGCM,
    MemoryPool
};

export type {
    EncryptedFormat
};
