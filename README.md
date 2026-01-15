# securex

A simple encryption library for JavaScript that provides true encryption for your tokens and data. Most developers use JWT tokens thinking they're secure, but JWT tokens are just base64 encoded - anyone can decode them instantly. securex solves this problem by providing actual AES-256-GCM encryption with a familiar API similar to JWT.

## Why Choose securex

The main security issue with JWT is that anyone can read the token payload because it's only base64 encoded, not encrypted. While JWT is great for authentication and authorization where the payload doesn't need to be secret, it's not suitable when you need to store sensitive information in tokens.

securex was built to address this specific problem. It provides the same convenient API as JWT (with `sign()` and `verify()` functions), but instead of just signing your data, it actually encrypts it using industry-standard AES-256-GCM encryption. This means your token payload remains completely unreadable without the secret key.

## How It Works

securex uses several proven technologies working together to provide secure encryption:

**AES-256-GCM Encryption**  
The core encryption algorithm is AES-256-GCM (Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode). This is the same encryption standard used by banks, governments, and security-focused organizations worldwide. GCM mode provides both encryption and authentication, which means it can detect if encrypted data has been tampered with.

**@noble/ciphers Library**  
Instead of implementing cryptography from scratch, securex uses the @noble/ciphers library, which is a well-audited and trusted cryptography library for JavaScript. This ensures the encryption implementation follows best practices and has been reviewed by security experts.

**Built-in Compression**  
Before encryption, securex compresses your data using a lossless LZ-based compression algorithm. This reduces the size of encrypted tokens by 30-70% for typical text and JSON data, making them more efficient to store and transmit. The compression is completely lossless, meaning your data is perfectly restored after decryption.

**Random Initialization Vectors**  
Every time you encrypt data, securex generates a random 12-byte initialization vector (IV). This ensures that even if you encrypt the same data twice with the same key, the encrypted output will be completely different. This is an important security feature that prevents pattern analysis attacks.

**Authentication Tags**  
The GCM mode automatically generates a 16-byte authentication tag for each encryption. This tag is verified during decryption and will cause an error if the encrypted data has been modified in any way. This protects against tampering and ensures data integrity.


## Installation

Install securex using npm:

```bash
npm install securex
```

That's it. The package has only one dependency (@noble/ciphers), which will be installed automatically.

## Quick Start

Here's how to get started with securex in just a few lines:

```javascript
import { generateKey, sign, verify } from 'securex';

// Step 1: Generate a secret key (do this once, save it securely)
const secretKey = await generateKey();
console.log('Save this key:', secretKey);

// Step 2: Encrypt some data with expiration
const encryptedToken = await sign('user-12345', secretKey, 60); // expires in 60 minutes

// Step 3: Decrypt and verify the data
const decryptedData = await verify(encryptedToken, secretKey);
console.log('Decrypted:', decryptedData); // 'user-12345'
```

## Usage Guide

### Generating a Secret Key

Before you can encrypt anything, you need a secret key. Generate one using the `generateKey()` function:

```javascript
import { generateKey } from 'securex';

const secretKey = await generateKey();
console.log(secretKey); // e5aadb9a85519a11f4c8... (64 characters)
```

The secret key is a 64-character hexadecimal string (32 bytes). You should generate this once and store it securely in your environment variables. Never commit it to version control or expose it in client-side code.

**Important:** Save this key in a secure place like an environment variable:

```javascript
// .env file
ENCRYPTION_KEY=your_generated_key_here

// In your code
const secretKey = process.env.ENCRYPTION_KEY;
```

### Encrypting and Decrypting Tokens

For simple token encryption without expiration, use `encryptToken()` and `decryptToken()`:

```javascript
import { encryptToken, decryptToken } from 'securex';

const secretKey = 'your-64-character-hex-key';
const token = 'my-sensitive-token';

// Encrypt the token
const encrypted = await encryptToken(token, secretKey);
console.log(encrypted); // Long encrypted string

// Decrypt the token
const decrypted = await decryptToken(encrypted, secretKey);
console.log(decrypted); // 'my-sensitive-token'
```

### Using Sign and Verify (JWT-like API)

If you want tokens with automatic expiration (similar to JWT), use `sign()` and `verify()`:

```javascript
import { sign, verify } from 'securex';

const secretKey = 'your-64-character-hex-key';

// Sign a token with 2 hours expiration
const signedToken = await sign('user-12345', secretKey, 120); // 120 minutes

// Verify the token (will throw error if expired)
try {
  const data = await verify(signedToken, secretKey);
  console.log('Valid token:', data); // 'user-12345'
} catch (error) {
  console.log('Token expired or invalid:', error.message);
}
```

The `sign()` function takes three parameters:
- `data`: The data you want to encrypt (can be a string, number, or any JSON-serializable value)
- `secretKey`: Your 64-character secret key
- `expiresIn`: Expiration time in minutes (default is 60 minutes)

The `verify()` function will automatically check if the token has expired and throw an error if it has.

### Encrypting Complex Data

You can encrypt any type of data (objects, arrays, numbers, etc.) using `encryptData()` and `decryptData()`:

```javascript
import { encryptData, decryptData } from 'securex';

const secretKey = 'your-64-character-hex-key';

const userData = {
  id: 12345,
  email: 'user@example.com',
  roles: ['admin', 'user'],
  settings: {
    theme: 'dark',
    notifications: true
  }
};

// Encrypt the entire object
const encrypted = await encryptData(userData, secretKey);

// Decrypt back to the original object
const decrypted = await decryptData(encrypted, secretKey);
console.log(decrypted); // Exact same object as userData
```

The data is automatically converted to JSON, compressed, and then encrypted. When you decrypt it, you get back the exact same data structure.

### Batch Operations

If you need to encrypt or decrypt multiple items at once, use the batch functions for better performance:

```javascript
import { batchEncrypt, batchDecrypt } from 'securex';

const secretKey = 'your-64-character-hex-key';
const tokens = ['token1', 'token2', 'token3', 'token4'];

// Encrypt all tokens in parallel
const encryptedTokens = await batchEncrypt(tokens, secretKey);

// Decrypt all tokens in parallel
const decryptedTokens = await batchDecrypt(encryptedTokens, secretKey);
```

Batch operations process all items in parallel, making them significantly faster than encrypting items one by one.

For encrypting multiple data objects:

```javascript
import { batchData, batchDataDecrypt } from 'securex';

const dataArray = [
  { id: 1, name: 'Alice' },
  { id: 2, name: 'Bob' },
  { id: 3, name: 'Charlie' }
];

const encrypted = await batchData(dataArray, secretKey);
const decrypted = await batchDataDecrypt(encrypted, secretKey);
```

## Complete API Reference

### Key Generation

**`generateKey()`**  
Generates a secure 64-character hexadecimal key for encryption.

- Returns: `Promise<string>` - A 64-character hex string
- Example: `const key = await generateKey();`

### Token Functions

**`encryptToken(token, secretKey)`**  
Encrypts a string token.

- Parameters:
  - `token` (string): The token to encrypt
  - `secretKey` (string): 64-character hex key
- Returns: `Promise<string>` - Encrypted token
- Example: `const encrypted = await encryptToken('my-token', key);`

**`decryptToken(encryptedToken, secretKey)`**  
Decrypts an encrypted token.

- Parameters:
  - `encryptedToken` (string): The encrypted token
  - `secretKey` (string): Same key used for encryption
- Returns: `Promise<string>` - Original token
- Throws: Error if decryption fails or token is corrupted
- Example: `const token = await decryptToken(encrypted, key);`

**`sign(data, secretKey, expiresIn)`**  
Encrypts data with automatic expiration (similar to JWT).

- Parameters:
  - `data` (any): Data to encrypt (string, number, object, etc.)
  - `secretKey` (string): 64-character hex key
  - `expiresIn` (number, optional): Expiration time in minutes (default: 60)
- Returns: `Promise<string>` - Encrypted token with expiration
- Example: `const token = await sign('user-123', key, 120);`

**`verify(signedToken, secretKey)`**  
Decrypts and verifies a signed token (similar to JWT verify).

- Parameters:
  - `signedToken` (string): The encrypted token
  - `secretKey` (string): Same key used for signing
- Returns: `Promise<any>` - Original data
- Throws: Error if token is expired or invalid
- Example: `const data = await verify(token, key);`

**`batchEncrypt(tokens, secretKey)`**  
Encrypts multiple tokens in parallel.

- Parameters:
  - `tokens` (string[]): Array of tokens to encrypt
  - `secretKey` (string): 64-character hex key
- Returns: `Promise<string[]>` - Array of encrypted tokens
- Example: `const encrypted = await batchEncrypt(['t1', 't2'], key);`

**`batchDecrypt(encryptedTokens, secretKey)`**  
Decrypts multiple tokens in parallel.

- Parameters:
  - `encryptedTokens` (string[]): Array of encrypted tokens
  - `secretKey` (string): Same key used for encryption
- Returns: `Promise<string[]>` - Array of original tokens
- Example: `const tokens = await batchDecrypt(encrypted, key);`

### Data Functions

**`encryptData(data, secretKey)`**  
Encrypts any type of data (objects, arrays, primitives).

- Parameters:
  - `data` (any): Data to encrypt (cannot be undefined)
  - `secretKey` (string): 64-character hex key
- Returns: `Promise<string>` - Encrypted data
- Example: `const encrypted = await encryptData({ id: 1 }, key);`

**`decryptData(encryptedData, secretKey)`**  
Decrypts data back to its original type.

- Parameters:
  - `encryptedData` (string): The encrypted data
  - `secretKey` (string): Same key used for encryption
- Returns: `Promise<any>` - Original data with original type
- Example: `const data = await decryptData(encrypted, key);`

**`batchData(dataArray, secretKey)`**  
Encrypts multiple data items in parallel.

- Parameters:
  - `dataArray` (any[]): Array of data items to encrypt
  - `secretKey` (string): 64-character hex key
- Returns: `Promise<string[]>` - Array of encrypted data
- Example: `const encrypted = await batchData([obj1, obj2], key);`

**`batchDataDecrypt(encryptedDataArray, secretKey)`**  
Decrypts multiple data items in parallel.

- Parameters:
  - `encryptedDataArray` (string[]): Array of encrypted data
  - `secretKey` (string): Same key used for encryption
- Returns: `Promise<any[]>` - Array of original data
- Example: `const data = await batchDataDecrypt(encrypted, key);`

## Error Handling

securex provides clear error messages to help you debug issues:

### Token Expired Error

When using `verify()`, if a token has expired, you'll get an error:

```javascript
try {
  const data = await verify(expiredToken, secretKey);
} catch (error) {
  if (error.message.includes('expired')) {
    console.log('Token has expired, please login again');
  }
}
```

### Decryption Errors

Common decryption errors and their causes:

```javascript
try {
  const data = await decryptToken(encrypted, secretKey);
} catch (error) {
  // Possible causes:
  // - Wrong secret key
  // - Corrupted encrypted data
  // - Invalid encrypted data format
  console.log('Decryption failed:', error.message);
}
```

**Common error causes:**
- Invalid secret key format (must be 64 hex characters)
- Using a different key for decryption than encryption
- Corrupted or modified encrypted data
- Passing non-string values where strings are expected

## Security Best Practices

### Storing Secret Keys

Never hardcode your secret key in your source code. Always use environment variables:

```javascript
// Good - using environment variables
const secretKey = process.env.ENCRYPTION_KEY;

// Bad - hardcoded key
const secretKey = 'abc123...'; // Never do this!
```

### Key Rotation

For maximum security, consider rotating your encryption keys periodically:

1. Generate a new key
2. Keep the old key for decrypting existing data
3. Use the new key for all new encryptions
4. Gradually re-encrypt old data with the new key

### Client-Side Usage

Be careful when using securex in client-side code. The secret key should never be exposed to the client. Only use securex on the client if:

- You're decrypting data that was encrypted on the server
- The key is specific to that user session and not reused
- You understand the security implications

For most use cases, encryption should happen on the server side.

## Frequently Asked Questions

**Q: How is the secret key generated?**  
A: The `generateKey()` function uses cryptographically secure random number generation to create a 32-byte (256-bit) key, which is then converted to a 64-character hexadecimal string.

**Q: Can I use the same key for both tokens and data?**  
A: Yes, you can use the same secret key for all encryption functions (tokens, data, signing, etc.).

**Q: What happens if I lose my secret key?**  
A: If you lose your secret key, you cannot decrypt any data that was encrypted with that key. Always back up your keys securely.

**Q: Can I change the expiration time after signing?**  
A: No, the expiration time is encrypted into the token. You would need to create a new token with a different expiration time.

**Q: Is it safe to use in production?**  
A: Yes, securex uses industry-standard encryption (AES-256-GCM) and the well-audited @noble/ciphers library. However, always follow security best practices like keeping your keys secure and using HTTPS.

**Q: How do I migrate from JWT to securex?**  
A: securex has a similar API to JWT. Replace `jwt.sign()` with `sign()` and `jwt.verify()` with `verify()`. The main difference is that you need to manage your encryption key securely.

**Q: Does this work with TypeScript?**  
A: Yes, securex includes full TypeScript type definitions.

**Q: What's the maximum data size I can encrypt?**  
A: There's no artificial limit imposed by securex, but very large data (multiple megabytes) may be slow to encrypt and should be handled carefully. For large files, consider encrypting them in chunks or using a different approach.


## Author

Built by [Shahwaiz Afzal](https://github.com/Shahwaiz24)

For bug reports and feature requests, please visit the [GitHub repository](https://github.com/Shahwaiz24/securex).
