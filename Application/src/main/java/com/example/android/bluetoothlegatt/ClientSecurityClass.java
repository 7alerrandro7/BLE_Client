package com.example.android.bluetoothlegatt;

import android.os.Environment;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class SecurityClass {

    public static final String TAG = "SecurityClass_LOG";
    final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    public static String Decrypt(byte[] text) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeyException {

        byte[] plainText = text;

        //
        //Gera uma semente
        String SecretSentence = "secreta";
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(SecretSentence.getBytes("UTF8"));

        //
        // gera uma chave para o DES
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56, sr);
        Key key = keyGen.generateKey();

        //
        // define um objeto de cifra DES e imprime o provider utilizado
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //
        // encripta utilizando a chave e o texto plano
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);

        return(new String(cipherText, "UTF-8"));

    }

}
