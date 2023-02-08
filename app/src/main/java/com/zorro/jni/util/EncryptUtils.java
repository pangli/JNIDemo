package com.zorro.jni.util;

import android.util.Log;

/**
 * Package:   com.sino.topsdk
 * ClassName: Encrypt
 * Created by Zorro on 2023/2/3 14:39.
 * Note:
 */
public class EncryptUtils {
    private static final String TAG = "EncryptUtils";

    static {
        try {
            System.loadLibrary("topsdk");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Unable to load encrypt utils jni native libraries");
        }
    }

    public static native String publicKeyStringFromJNI();

    // AES加密, CBC, PKCS5Padding
    public static native String encrypt(String str);

    // AES解密, CBC, PKCS5Padding
    public static native String decrypt(String str);

}
