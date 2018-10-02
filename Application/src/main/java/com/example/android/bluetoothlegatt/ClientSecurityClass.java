package com.example.android.bluetoothlegatt;

import android.os.Environment;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClientSecurityClass {

    public static final String TAG = "SecurityClass_LOG";
    //final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    public static String Decrypt(byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        Log.d(TAG, "Bytes = " + text);

        byte [] key = "AAAAA".getBytes("ASCII");

        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        rc4.init(Cipher.DECRYPT_MODE, rc4Key);

        byte [] cipherText = rc4.update(text);

        return(new String(cipherText, "ASCII"));

    }

    public static byte[] Encrypt(String text) throws UnsupportedEncodingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        byte[] plainText = text.getBytes("ASCII");

        Log.i(TAG, text);

        byte [] key = "AAAAA".getBytes("ASCII");

        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        rc4.init(Cipher.ENCRYPT_MODE, rc4Key);

        byte [] cipherText = rc4.update(plainText);

        // converte o cipherText para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < cipherText.length; i++) {
            String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        // imprime o ciphertext em hexadecimal
        Log.i(TAG, buf.toString());

        return(cipherText);

    }

}
