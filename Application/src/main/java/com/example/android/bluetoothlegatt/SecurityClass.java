package com.example.android.bluetoothlegatt;

import android.os.Environment;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SecurityClass {

    public static final String TAG = "SecurityClass_LOG";
    final static String path = Environment.getExternalStorageDirectory().getPath() + "/keys/";

    public static String Decrypt(byte[] text) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, InvalidKeyException {

        byte[] plainText = text;

        //
        // Recuperando a key de um arquivo
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(path + "KeyFile.key"));
        Key key = (Key)in.readObject();
        in.close();

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
