package com.pedrouid.crypto;

import android.content.Context;
import android.net.Uri;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class Util {
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
}
