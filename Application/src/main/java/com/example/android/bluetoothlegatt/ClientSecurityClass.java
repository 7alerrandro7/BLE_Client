package com.example.android.bluetoothlegatt;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class ClientSecurityClass {

    public static final String TAG = "SecurityClass_LOG";

    public static String Decrypt(byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        Log.d(TAG, "Bytes = " + text.toString());

        byte [] key = "AAAAA".getBytes("ASCII");

        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        rc4.init(Cipher.DECRYPT_MODE, rc4Key);

        byte [] cipherText = rc4.update(text);

        return(new String(cipherText, "ASCII"));

    }

    public static byte[] Decrypt(byte[] text, SecretKeySpec Ksession) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        Log.d(TAG, "Bytes = " + text.toString());

        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.DECRYPT_MODE, Ksession);

        byte [] cipherText = rc4.update(text);

        return(cipherText);

    }

    public static byte[] Encrypt(String text) throws UnsupportedEncodingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        byte[] plainText = text.getBytes("ASCII");

        Log.i(TAG, text);

        byte [] key = "AAAAA".getBytes("ASCII");

        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4Key = new SecretKeySpec(key, "RC4");
        rc4.init(Cipher.ENCRYPT_MODE, rc4Key);

        byte [] cipherText = rc4.update(plainText);

        return(cipherText);

    }

    public static byte[] Encrypt(byte[] plainText, SecretKeySpec Ksession){
        Cipher rc4 = null;
        try {
            rc4 = Cipher.getInstance("RC4");
            rc4.init(Cipher.ENCRYPT_MODE, Ksession);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e ) {
            e.printStackTrace();
        }

        byte [] cipherText = rc4.update(plainText);

        return(cipherText);
    }

}
