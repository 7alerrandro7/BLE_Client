package com.example.android.bluetoothlegatt;

public class Obj {

    public String obj_id;
    public byte[] Kauth_sddl;
    public byte[] Kauth_obj;

    public Obj(String obj_id, byte[] kauth_sddl, byte[] kauth_obj) {
        this.obj_id = obj_id;
        Kauth_sddl = kauth_sddl;
        Kauth_obj = kauth_obj;
    }
}
