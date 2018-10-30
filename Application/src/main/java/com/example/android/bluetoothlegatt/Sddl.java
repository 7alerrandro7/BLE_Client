package com.example.android.bluetoothlegatt;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Sddl {

    public static final String TAG = "SDDL_LOG";

    private ArrayList<Hub> hubList = new ArrayList<>();
    private ArrayList<Obj> objList = new ArrayList<>();

    private static SecretKeySpec Kauth_sddl;


    static {
        try {
            Kauth_sddl = new SecretKeySpec(("Kauth_sddl").getBytes("ASCII"), "hmacMD5");
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
                Package_Auth PACK = createPackage(obj_id, hub_id, obj.Kcipher_obj, obj.Kauth_obj);
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

    private Package_Auth createPackage(String obj_id, String hub_id, byte[] Kcipher_obj, byte[] Kauth_obj){
        String OTPChallenge = generateOTPChallenge(13);
        SecretKeySpec Ksession = Ksession(11);

        byte[] OTP = generateOTP(obj_id, hub_id, OTPChallenge, Kauth_obj);
        byte[] PackageK = GenerateST_PackageK(OTPChallenge, Ksession, Kcipher_obj);
        byte[] Package_K_HMAC = SignST_Package_K(PackageK, Kauth_sddl);

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

    private byte[] generateOTP(String obj_id, String hub_id, String OTPChallenge, byte[] Kauth_obj){
        String KAUTH = null;
        try {
            KAUTH = new String(Kauth_obj, "ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String concat = obj_id + hub_id + OTPChallenge + KAUTH;
        Log.d(TAG, "STRING OTP: " + concat);

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

    private byte[] CreatePackageK(String OTPChallenge, SecretKeySpec Ksession){
        byte[] otp = OTPChallenge.getBytes();
        byte[] ksession = Ksession.getEncoded();
        Log.d(TAG, "Ksession_BYTE: ");
        print_hex(ksession);

        byte[] resp = new byte[otp.length + ksession.length];
        System.arraycopy(otp, 0, resp, 0, otp.length);
        System.arraycopy(ksession, 0, resp, otp.length, ksession.length);

        return resp;
    }

    private byte[] GenerateST_PackageK(String OTPChallenge, SecretKeySpec Ksession, byte[] Kcipher_obj){
        byte[] PackageK = CreatePackageK(OTPChallenge, Ksession);
        byte[] PackK = Encrypt(PackageK, Kcipher_obj);
        return PackK;
    }

    private byte[] Encrypt(byte[] Package, byte[] Kcipher_obj) {

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

        byte [] cipherText = rc4.update(Package);

        return(cipherText);
    }

    private byte[] SignST_Package_K(byte[] PackageK, SecretKeySpec Kauth_sddl){
        byte[] bytes = new byte[0];
        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_sddl);
            bytes = mac.doFinal(PackageK);
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }
        return bytes;
    }

    public void print_hex(byte[] cipherText) {
        if(cipherText != null){
            StringBuffer buf = new StringBuffer();
            for(int i = 0; i < cipherText.length; i++) {
                String hex = Integer.toHexString(0x0100 + (cipherText[i] & 0x00FF)).substring(1);
                buf.append((hex.length() < 2 ? "0" : "") + hex);
            }

            // imprime o ciphertext em hexadecimal
            Log.i(TAG, "Texto bytes: " + buf.toString());
        }
    }

    private byte[] convertToBytes(Object object) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(object);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
