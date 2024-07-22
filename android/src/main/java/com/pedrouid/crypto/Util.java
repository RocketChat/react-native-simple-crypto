package com.pedrouid.crypto;

import android.content.Context;
import android.net.Uri;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Util extends ReactContextBaseJavaModule {

     public Util(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "Shared";
    }

    @ReactMethod
    public void calculateFileChecksum(String filePath, Promise promise) {
        try {
            String result = calculateFileChecksum(getReactApplicationContext(),filePath );
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    @ReactMethod
    public void getRandomValues(int length, Promise promise) {
        try {
            String result = getRandomValues(length);
            promise.resolve(result);
        } catch (Exception e) {
            promise.reject("-1", e.getMessage());
        }
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static InputStream getInputStream(Context context, String inputFile) throws Exception {
        if (inputFile.startsWith("content://")) {
            return context.getContentResolver().openInputStream(Uri.parse(inputFile));
        } else if (inputFile.startsWith("file://")) {
            String normalizedFilePath = inputFile.substring(7); // Remove the "file://" prefix
            return new FileInputStream(new File(normalizedFilePath));
        } else {
            return new FileInputStream(new File(inputFile)); // Handle plain file paths
        }
    }

    public static String calculateFileChecksum(Context context, String filePath) throws Exception {
        InputStream inputStream = getInputStream(context, filePath);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            digest.update(buffer, 0, bytesRead);
        }
        inputStream.close();
        byte[] hash = digest.digest();
        return bytesToHex(hash);
    }

    public static String getRandomValues(int length) {
        final String alphanumericChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphanumericChars.charAt(random.nextInt(alphanumericChars.length())));
        }
        return sb.toString();
    }
}
