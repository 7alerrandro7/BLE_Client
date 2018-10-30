package com.example.android.bluetoothlegatt;

import javax.crypto.spec.SecretKeySpec;

public class AvailableObj {

    public String obj_id;
    SecretKeySpec Ksession;
    byte[] OTP;

    public AvailableObj(String obj_id, SecretKeySpec ksession, byte[] OTP) {
        this.obj_id = obj_id;
        Ksession = ksession;
        this.OTP = OTP;
    }

}
