import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  NativeModules,
} from 'react-native';
import SimpleCrypto from 'react-native-simple-crypto';

const PLAINTEXT = 'Hello, AES encryption!';
const KEY_HEX = '00112233445566778899aabbccddeeff'; // 16 bytes (128 bits)
const IV_HEX = '0102030405060708'; // 8 bytes (for demonstration, but AES usually expects 16 bytes IV)
const PBKDF2_PASSWORD = 'password123';
const PBKDF2_SALT = 'saltysalt';
const PBKDF2_ITERATIONS = 10000;
const PBKDF2_KEYLEN = 32; // 32 bytes = 256 bits
const PBKDF2_ALGORITHM = 'SHA256';
const RSA_MESSAGE = 'Hello, RSA!';
const RSA_KEY_SIZE = 2048;
const SHA_MESSAGE = 'Hello, SHA!';
const RANDOM_BYTES_LENGTH = 16;
const HMAC_MESSAGE = 'Hello, HMAC!';
const HMAC_KEY = 'supersecretkey';

function hexToArrayBuffer(hex: string) {
  return SimpleCrypto.utils.convertHexToArrayBuffer(hex);
}

export default function App() {
  const [encrypted, setEncrypted] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [error, setError] = useState('');
  const [pbkdf2Key, setPbkdf2Key] = useState('');
  const [pbkdf2Error, setPbkdf2Error] = useState('');
  const [rsaPublicKey, setRsaPublicKey] = useState('');
  const [rsaPrivateKey, setRsaPrivateKey] = useState('');
  const [rsaEncrypted, setRsaEncrypted] = useState('');
  const [rsaDecrypted, setRsaDecrypted] = useState('');
  const [rsaError, setRsaError] = useState('');
  const [rsaJwk, setRsaJwk] = useState('');
  const [rsaImportedPem, setRsaImportedPem] = useState('');
  const [rsaUtilsError, setRsaUtilsError] = useState('');
  const [sha1, setSha1] = useState('');
  const [sha256, setSha256] = useState('');
  const [sha512, setSha512] = useState('');
  const [shaError, setShaError] = useState('');
  const [randomBytesHex, setRandomBytesHex] = useState('');
  const [randomBytesBase64, setRandomBytesBase64] = useState('');
  const [randomBytesError, setRandomBytesError] = useState('');
  const [hmac256, setHmac256] = useState('');
  const [hmacError, setHmacError] = useState('');

  useEffect(() => {
    async function testAES() {
      try {
        const key = hexToArrayBuffer(KEY_HEX);
        const iv = hexToArrayBuffer(IV_HEX);
        const textBuffer =
          SimpleCrypto.utils.convertUtf8ToArrayBuffer(PLAINTEXT);

        // Encrypt
        const encryptedBuffer = await SimpleCrypto.AES.encrypt(
          textBuffer,
          key,
          iv,
        );
        const encryptedBase64 =
          SimpleCrypto.utils.convertArrayBufferToBase64(encryptedBuffer);
        setEncrypted(encryptedBase64);

        // Decrypt
        const decryptedBuffer = await SimpleCrypto.AES.decrypt(
          encryptedBuffer,
          key,
          iv,
        );
        const decryptedText =
          SimpleCrypto.utils.convertArrayBufferToUtf8(decryptedBuffer);
        setDecrypted(decryptedText);
      } catch (e) {
        const err = e as Error;
        setError(err.message || String(e));
      }
    }
    testAES();

    async function testPBKDF2() {
      try {
        const derivedKeyBuffer = await SimpleCrypto.PBKDF2.hash(
          PBKDF2_PASSWORD,
          PBKDF2_SALT,
          PBKDF2_ITERATIONS,
          PBKDF2_KEYLEN,
          PBKDF2_ALGORITHM,
        );
        const derivedKeyHex =
          SimpleCrypto.utils.convertArrayBufferToHex(derivedKeyBuffer);
        setPbkdf2Key(derivedKeyHex);
      } catch (e) {
        const err = e as Error;
        setPbkdf2Error(err.message || String(e));
      }
    }
    testPBKDF2();

    async function testRSA() {
      try {
        // Generate key pair
        console.log(NativeModules.RsaUtils);
        const keyPair = await SimpleCrypto.RSA.generateKeys(RSA_KEY_SIZE);
        setRsaPublicKey(keyPair.public);
        setRsaPrivateKey(keyPair.private);

        // Encrypt with public key
        const encrypted = await SimpleCrypto.RSA.encrypt(
          RSA_MESSAGE,
          keyPair.public,
        );
        setRsaEncrypted(encrypted);

        // Decrypt with private key
        const decrypted = await SimpleCrypto.RSA.decrypt(
          encrypted,
          keyPair.private,
        );
        setRsaDecrypted(decrypted);
      } catch (e) {
        const err = e as Error;
        setRsaError(err.message || String(e));
      }
    }
    testRSA();

    async function testSHA() {
      try {
        const sha1Hash = await SimpleCrypto.SHA.sha1(SHA_MESSAGE);
        setSha1(sha1Hash);
        const sha256Hash = await SimpleCrypto.SHA.sha256(SHA_MESSAGE);
        setSha256(sha256Hash);
        const sha512Hash = await SimpleCrypto.SHA.sha512(SHA_MESSAGE);
        setSha512(sha512Hash);
      } catch (e) {
        const err = e as Error;
        setShaError(err.message || String(e));
      }
    }
    testSHA();

    async function testRandomBytes() {
      try {
        const bytes = await SimpleCrypto.utils.randomBytes(RANDOM_BYTES_LENGTH);
        setRandomBytesHex(SimpleCrypto.utils.convertArrayBufferToHex(bytes));
        setRandomBytesBase64(
          SimpleCrypto.utils.convertArrayBufferToBase64(bytes),
        );
      } catch (e) {
        const err = e as Error;
        setRandomBytesError(err.message || String(e));
      }
    }
    testRandomBytes();

    async function testHMAC() {
      try {
        const messageBuffer =
          SimpleCrypto.utils.convertUtf8ToArrayBuffer(HMAC_MESSAGE);
        const keyBuffer = SimpleCrypto.utils.convertUtf8ToArrayBuffer(HMAC_KEY);
        const hmacBuffer = await SimpleCrypto.HMAC.hmac256(
          messageBuffer,
          keyBuffer,
        );
        setHmac256(SimpleCrypto.utils.convertArrayBufferToHex(hmacBuffer));
      } catch (e) {
        const err = e as Error;
        setHmacError(err.message || String(e));
      }
    }
    testHMAC();
  }, []);

  useEffect(() => {
    async function testRSAUtils(publicKey: string) {
      try {
        // Export public key to JWK
        const jwk = await SimpleCrypto.RSA.exportKey(publicKey);
        setRsaJwk(JSON.stringify(jwk, null, 2));

        // Import JWK back to PEM
        const importedPem = await SimpleCrypto.RSA.importKey(jwk);
        setRsaImportedPem(importedPem);
      } catch (e) {
        const err = e as Error;
        setRsaUtilsError(err.message || String(e));
      }
    }

    // Only run RSA Utils test after RSA key is generated
    if (rsaPublicKey) {
      testRSAUtils(rsaPublicKey);
    }
  }, [rsaPublicKey]);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>AES Encrypt/Decrypt Example</Text>
      <Text style={styles.label}>Original:</Text>
      <Text style={styles.value}>{PLAINTEXT}</Text>
      <Text style={styles.label}>Encrypted (Base64):</Text>
      <Text style={styles.value}>{encrypted}</Text>
      <Text style={styles.label}>Decrypted:</Text>
      <Text style={styles.value}>{decrypted}</Text>
      {error ? <Text style={styles.error}>Error: {error}</Text> : null}

      <Text style={[styles.title, { marginTop: 40 }]}>PBKDF2 Example</Text>
      <Text style={styles.label}>Password:</Text>
      <Text style={styles.value}>{PBKDF2_PASSWORD}</Text>
      <Text style={styles.label}>Salt:</Text>
      <Text style={styles.value}>{PBKDF2_SALT}</Text>
      <Text style={styles.label}>Iterations:</Text>
      <Text style={styles.value}>{PBKDF2_ITERATIONS}</Text>
      <Text style={styles.label}>Key Length (bytes):</Text>
      <Text style={styles.value}>{PBKDF2_KEYLEN}</Text>
      <Text style={styles.label}>Algorithm:</Text>
      <Text style={styles.value}>{PBKDF2_ALGORITHM}</Text>
      <Text style={styles.label}>Derived Key (Hex):</Text>
      <Text style={styles.value}>{pbkdf2Key}</Text>
      {pbkdf2Error ? (
        <Text style={styles.error}>PBKDF2 Error: {pbkdf2Error}</Text>
      ) : null}

      <Text style={[styles.title, { marginTop: 40 }]}>RSA Example</Text>
      <Text style={styles.label}>Original Message:</Text>
      <Text style={styles.value}>{RSA_MESSAGE}</Text>
      <Text style={styles.label}>Public Key:</Text>
      <Text style={styles.value}>{rsaPublicKey}</Text>
      <Text style={styles.label}>Private Key:</Text>
      <Text style={styles.value}>{rsaPrivateKey}</Text>
      <Text style={styles.label}>Encrypted (Base64):</Text>
      <Text style={styles.value}>{rsaEncrypted}</Text>
      <Text style={styles.label}>Decrypted:</Text>
      <Text style={styles.value}>{rsaDecrypted}</Text>
      {rsaError ? (
        <Text style={styles.error}>RSA Error: {rsaError}</Text>
      ) : null}

      <Text style={[styles.title, { marginTop: 40 }]}>RSA Utils Example</Text>
      <Text style={styles.label}>Exported Public Key (JWK):</Text>
      <Text style={styles.value}>{rsaJwk}</Text>
      <Text style={styles.label}>Imported PEM from JWK:</Text>
      <Text style={styles.value}>{rsaImportedPem}</Text>
      {rsaUtilsError ? (
        <Text style={styles.error}>RSA Utils Error: {rsaUtilsError}</Text>
      ) : null}

      <Text style={[styles.title, { marginTop: 40 }]}>SHA Example</Text>
      <Text style={styles.label}>Original Message:</Text>
      <Text style={styles.value}>{SHA_MESSAGE}</Text>
      <Text style={styles.label}>SHA-1:</Text>
      <Text style={styles.value}>{sha1}</Text>
      <Text style={styles.label}>SHA-256:</Text>
      <Text style={styles.value}>{sha256}</Text>
      <Text style={styles.label}>SHA-512:</Text>
      <Text style={styles.value}>{sha512}</Text>
      {shaError ? (
        <Text style={styles.error}>SHA Error: {shaError}</Text>
      ) : null}

      <Text style={[styles.title, { marginTop: 40 }]}>
        Random Bytes Example
      </Text>
      <Text style={styles.label}>Length:</Text>
      <Text style={styles.value}>{RANDOM_BYTES_LENGTH}</Text>
      <Text style={styles.label}>Random Bytes (Hex):</Text>
      <Text style={styles.value}>{randomBytesHex}</Text>
      <Text style={styles.label}>Random Bytes (Base64):</Text>
      <Text style={styles.value}>{randomBytesBase64}</Text>
      {randomBytesError ? (
        <Text style={styles.error}>Random Bytes Error: {randomBytesError}</Text>
      ) : null}

      <Text style={[styles.title, { marginTop: 40 }]}>HMAC Example</Text>
      <Text style={styles.label}>Message:</Text>
      <Text style={styles.value}>{HMAC_MESSAGE}</Text>
      <Text style={styles.label}>Key:</Text>
      <Text style={styles.value}>{HMAC_KEY}</Text>
      <Text style={styles.label}>HMAC-SHA256 (Hex):</Text>
      <Text style={styles.value}>{hmac256}</Text>
      {hmacError ? (
        <Text style={styles.error}>HMAC Error: {hmacError}</Text>
      ) : null}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
    marginTop: 50,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 22,
    fontWeight: 'bold',
    marginBottom: 24,
  },
  label: {
    fontWeight: 'bold',
    marginTop: 16,
  },
  value: {
    fontSize: 16,
    marginTop: 4,
    color: '#333',
  },
  error: {
    color: 'red',
    marginTop: 24,
    fontWeight: 'bold',
  },
});
