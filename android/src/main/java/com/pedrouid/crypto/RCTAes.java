package com.pedrouid.crypto;

import android.content.Context;
import android.util.Base64;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RCTAes extends ReactContextBaseJavaModule {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final String FILE_CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private static final int BUFFER_SIZE = 4096;

    public RCTAes(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RCTAes";
    }

    @ReactMethod
    public void encrypt(String dataBase64, String keyBase64, String ivBase64, Promise promise) {
        try {
            String result = encrypt(dataBase64, keyBase64, ivBase64);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decrypt(String data, String pwd, String iv, Promise promise) {
        try {
            String strs = decrypt(data, pwd, iv);
            promise.resolve(strs);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void encryptFile(String filePath, String base64UrlKey, String base64Iv, Promise promise) {
        try {
            String outputFilePath = encryptFile(filePath, base64UrlKey, base64Iv);
            promise.resolve(outputFilePath);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void decryptFile(String filePath, String base64UrlKey, String base64Iv, Promise promise) {
        try {
            String outputFilePath = decryptFile(filePath, base64UrlKey, base64Iv);
            promise.resolve(outputFilePath);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomUuid(Promise promise) {
        try {
            String result = UUID.randomUUID().toString();
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void randomKey(Integer length, Promise promise) {
        try {
            byte[] key = new byte[length];
            SecureRandom rand = new SecureRandom();
            rand.nextBytes(key);
            String keyHex = Util.bytesToHex(key);
            promise.resolve(keyHex);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    final static IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // AES block size
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String textBase64, String hexKey, String hexIv) throws Exception {
        if (textBase64 == null || textBase64.length() == 0) {
            return null;
        }

        byte[] key = Hex.decode(hexKey);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, hexIv == null ? emptyIvSpec : new IvParameterSpec(Hex.decode(hexIv)));
        byte[] encrypted = cipher.doFinal(Base64.decode(textBase64, Base64.DEFAULT));
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    public static String decrypt(String ciphertext, String hexKey, String hexIv) throws Exception {
        if(ciphertext == null || ciphertext.length() == 0) {
            return null;
        }

        byte[] key = Hex.decode(hexKey);
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, hexIv == null ? emptyIvSpec : new IvParameterSpec(Hex.decode(hexIv)));
        byte[] decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.DEFAULT));
        return Base64.encodeToString(decrypted, Base64.NO_WRAP);
    }

    public static String processFile(Context context, String inputFile, String base64UrlKey, String base64Iv, String mode) throws Exception {
        // Decode the key and IV using URL-safe and no-wrap flags
        byte[] key = Base64.decode(base64UrlKey, Base64.URL_SAFE | Base64.NO_WRAP);
        byte[] iv = Base64.decode(base64Iv, Base64.NO_WRAP);
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        // Initialize the cipher
        Cipher cipher = Cipher.getInstance(FILE_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(mode.equals("encrypt") ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        // Create a temporary output file in the cache directory
        File outputFileObj = new File(context.getCacheDir(), "processed_" + UUID.randomUUID().toString());

        // File streams setup
        try (InputStream is = Util.getInputStream(context, inputFile);
             FileOutputStream fos = new FileOutputStream(outputFileObj)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int numBytesRead;

            while ((numBytesRead = is.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, numBytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) {
                fos.write(finalBytes);
            }
        } catch (Exception ex) {
            outputFileObj.delete(); // Ensure temporary file is removed on error
            throw ex;
        }

        if ("decrypt".equals(mode)) {
            // Overwrite the input file with the decrypted file
            try (InputStream is2 = new FileInputStream(outputFileObj);
                 FileOutputStream fos = new FileOutputStream(inputFile.startsWith("file://") ? inputFile.substring(7) : inputFile)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int numBytesRead;

                while ((numBytesRead = is2.read(buffer)) != -1) {
                    fos.write(buffer, 0, numBytesRead);
                }
            }
            outputFileObj.delete(); // Remove the temporary file after overwriting
            return inputFile;
        } else {
            return "file://" + outputFileObj.getAbsolutePath();
        }
    }

    public String encryptFile(String inputFile, String base64UrlKey, String base64Iv) throws Exception {
        return processFile(getReactApplicationContext(), inputFile, base64UrlKey, base64Iv, "encrypt");
    }

    public String decryptFile(String inputFile, String base64UrlKey, String base64Iv) throws Exception {
        return processFile(getReactApplicationContext(), inputFile, base64UrlKey, base64Iv, "decrypt");
    }
}
