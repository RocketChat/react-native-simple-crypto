import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, ScrollView } from 'react-native';
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
  }, []);

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
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
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
