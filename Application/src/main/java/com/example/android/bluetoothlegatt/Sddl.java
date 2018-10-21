package com.example.android.bluetoothlegatt;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Sddl {

    public static final String TAG = "SDDL_LOG";

    private ArrayList<Hub> hubList = new ArrayList<>();
    private ArrayList<Obj> objList = new ArrayList<>();

    private static byte[] Kauth_sddl;


    static {
        try {
            Kauth_sddl = "Kauth_sddl".getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }



    public Sddl(String obj_id, String hub_id) {
        if (hubList.isEmpty()){
            hubList = new ArrayList<>();
        }
        hubList.add(new Hub(obj_id, hub_id));

        Log.d(TAG, "Hub: " + hub_id + " Obj_id: " + obj_id);

        if (objList.isEmpty()){
            objList = new ArrayList<>();
        }
        byte[] Kauth_obj = new byte[0];
        byte[] Kcipher_obj = new byte[0];
        try {
            Kauth_obj = "Kauth_obj".getBytes("ASCII");
            Kcipher_obj = "Kcipher_obj".getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        objList.add(new Obj(obj_id, Kauth_obj, Kcipher_obj));
    }

    public Package_Auth get_authorization(String obj_id, String hub_id){
        if(checkAddress(obj_id, hub_id)){
            Obj obj = DB_Get_Kauth_Kcipher(obj_id);
            if(obj != null){
                Package_Auth PACK = createPackage(obj_id, hub_id, obj.Kcipher_obj);
                return PACK;
            }else{
                Log.d(TAG, "Failed to check keys of IoT (Object)");
            }
        }else{
            Log.d(TAG, "Hub without permission!");
        }
        return null;
    }

    private boolean checkAddress(String obj_id, String hub_id){
        for(int i = 0; i< hubList.size(); i++){
            Log.d(TAG, "Lista Obj_id: " + hubList.get(i).obj_id + "  -Obj_id: "+ obj_id);
            Log.d(TAG, "Lista Hub_id: " + hubList.get(i).hub_id + "  -HUb_id: "+ hub_id);
            if(hubList.get(i).obj_id.equals(obj_id) && hubList.get(i).hub_id.equals(hub_id)){
                return true;
            }
        }
        return false;
    }

    private Obj DB_Get_Kauth_Kcipher(String obj_id){
        for(int i=0; i<objList.size(); i++){
            if(objList.get(i).obj_id == obj_id){
                return objList.get(i);
            }
        }
        return null;
    }

    private Package_Auth createPackage(String obj_id, String hub_id, byte[] Kcipher_obj){
        String OTPChallenge = generateOTPChallenge(5);
        SecretKeySpec Ksession = Ksession(5);
        byte[] OTP = generateOTP(obj_id, hub_id, OTPChallenge);

        Log.d(TAG, "OTPChallenge " + OTPChallenge);
        Log.d(TAG, "Ksession: " + Ksession);

        byte[] PackageK = GenerateST_PackageK(OTPChallenge, Ksession, Kcipher_obj);
        Log.d(TAG, "PackageK: " + PackageK);

        byte[] Package_K_HMAC = SignST_Package_K(PackageK, Kauth_sddl);

        Log.d(TAG, "PackageK_HMAC: " + Package_K_HMAC);
        Package_Auth PACK = new Package_Auth(OTP, Ksession, PackageK, Package_K_HMAC);

        return(PACK);

    }

    private String generateOTPChallenge(int size){
        StringBuilder generatedToken = new StringBuilder();
        try {
            SecureRandom number = SecureRandom.getInstance("SHA1PRNG");
            // Generate 20 integers 0..20
            for (int i = 0; i < size; i++) {
                generatedToken.append(number.nextInt(9));
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return generatedToken.toString();
    }

    private byte[] generateOTP(String obj_id, String hub_id, String OTPChallenge){
        String concat = obj_id.substring(6,7) + hub_id.substring(0, 1) + OTPChallenge;

        byte[] OTP = new byte[0];
        try {
            OTP = concat.getBytes("UTF8");
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(OTP);
            OTP = messageDigest.digest();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return OTP;
    }

    private SecretKeySpec Ksession(int size){
        String otp = generateOTPChallenge(size);
        byte[] seed = new byte[0];

        try {
            seed = otp.getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        SecretKeySpec sessionKey = new SecretKeySpec(seed, "RC4");

        return sessionKey;

    }

    private byte[] GenerateST_PackageK(String OTPChallenge, SecretKeySpec Ksession, byte[] Kcipher_obj){
        String Package = OTPChallenge + Ksession;

        byte[] PackageK = new byte[0];
        try {
            PackageK = Encrypt(Package, Kcipher_obj);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return PackageK;
    }

    private byte[] Encrypt(String Package, byte[] Kcipher_obj) throws UnsupportedEncodingException {

        byte[] pack = Package.getBytes("ASCII");

        Cipher rc4 = null;
        try {
            rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(Kcipher_obj, "RC4");
            rc4.init(Cipher.ENCRYPT_MODE, rc4Key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte [] cipherText = rc4.update(pack);

        return(cipherText);
    }

    private byte[] SignST_Package_K(byte[] PackageK, byte[] Kauth_sddl){
        byte[] PackageK_HMAC = new byte[0];
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(PackageK);
            PackageK_HMAC = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return PackageK_HMAC;
    }

    public void print_hex(byte[] cipherText) {
        if(cipherText != null){
            StringBuffer buf = new StringBuffer();
            for(int i = 0; i < cipherText.length; i++) {
                String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
                buf.append((hex.length() < 2 ? "0" : "") + hex);
            }

            // imprime o ciphertext em hexadecimal
            Log.i(TAG, "Texto criptografado: " + buf.toString());
        }
    }
}
