package com.example.android.bluetoothlegatt;

public class Obj {

    public String obj_id;
    public byte[] Kauth_obj;
    public byte[] Kcipher_obj;

    public Obj(String obj_id, byte[] kauth_obj, byte[] kcipher_obj) {
        this.obj_id = obj_id;
        Kauth_obj = kauth_obj;
        Kcipher_obj = kcipher_obj;
    }
}
