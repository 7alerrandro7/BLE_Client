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
    //final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    public static String Decrypt(byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {

        Log.d(TAG, "Bytes = " + text.toString());

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
        if(cipherText != null){
            StringBuffer buf = new StringBuffer();
            for(int i = 0; i < cipherText.length; i++) {
                String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
                buf.append((hex.length() < 2 ? "0" : "") + hex);
            }

            // imprime o ciphertext em hexadecimal
            Log.i(TAG, "Texto criptografado: " + buf.toString());
        }

        return(cipherText);

    }

}
