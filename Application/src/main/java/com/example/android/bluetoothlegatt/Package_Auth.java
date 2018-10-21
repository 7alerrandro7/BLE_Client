package com.example.android.bluetoothlegatt;

import javax.crypto.spec.SecretKeySpec;

public class Package_Auth {

    byte[] OTP;
    SecretKeySpec Ksession;
    byte[] Package;
    byte[] Package_HMAC;

    public Package_Auth(byte[] OTP, SecretKeySpec ksession, byte[] aPackage, byte[] package_HMAC) {
        this.OTP = OTP;
        Ksession = ksession;
        Package = aPackage;
        Package_HMAC = package_HMAC;
    }
}
