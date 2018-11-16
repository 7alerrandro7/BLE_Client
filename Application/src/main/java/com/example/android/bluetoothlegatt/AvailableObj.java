package com.example.android.bluetoothlegatt;

import javax.crypto.spec.SecretKeySpec;

public class AvailableObj {

    private String obj_id_random;
    private String obj_id_fix;
    private SecretKeySpec Ksession;
    private byte[] OTP;
    private byte[] timestamp;

    public AvailableObj(String obj_id, SecretKeySpec ksession, byte[] OTP) {
        this.obj_id_random = obj_id;
        Ksession = ksession;
        this.OTP = OTP;
    }

    public AvailableObj(String obj_id_fix) {
        this.obj_id_fix = obj_id_fix;
    }

    public AvailableObj(String obj_id_fix, String obj_id_random) {
        this.obj_id_fix = obj_id_fix;
        this.obj_id_random = obj_id_random;
    }

    public void setTimestamp(byte[] timestamp) {
        this.timestamp = timestamp;
    }

    public void setObj_id_fix(String obj_id_fix) {
        this.obj_id_fix = obj_id_fix;
    }

    public void setOTP(byte[] OTP) {
        this.OTP = OTP;
    }

    public void setKsession(SecretKeySpec ksession) {
        Ksession = ksession;
    }

    public void setObj_id_random(String obj_id_random) {
        this.obj_id_random = obj_id_random;
    }

    public String getObj_id_random() {
        return obj_id_random;
    }

    public String getObj_id_fix() {
        return obj_id_fix;
    }

    public SecretKeySpec getKsession() {
        return Ksession;
    }

    public byte[] getOTP() {
        return OTP;
    }

    public byte[] getTimestamp() {
        return timestamp;
    }
}
