package com.example.android.bluetoothlegatt;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

public class Sddl {

    public static final String TAG = "SDDL_LOG";

    private ArrayList<Hub> hubList;
    private ArrayList<Obj> objList;

    public Sddl(String obj_id, String hub_id) {
        if (hubList.isEmpty()){
            hubList = new ArrayList<>();
        }
        hubList.add(new Hub(obj_id, hub_id));

        if (objList.isEmpty()){
            objList = new ArrayList<>();
        }
        byte[] Kauth_sddl = new byte[0];
        byte[] Kauth_obj = new byte[0];
        try {
            Kauth_sddl = "Kauth_sddl".getBytes("ASCII");
            Kauth_obj = "Kauth_obj".getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        objList.add(new Obj(obj_id, Kauth_sddl, Kauth_obj));
    }

    public byte[] get_authorization(String obj_id, String hub_id){
        if(checkAddress(obj_id, hub_id)){
            Obj obj = checkKeys(obj_id);
            if(obj != null){

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
            if(hubList.get(i).obj_id == obj_id && hubList.get(i).hub_id == hub_id){
                return true;
            }
        }
        return false;
    }

    private Obj checkKeys(String obj_id){
        for(int i=0; i<objList.size(); i++){
            if(objList.get(i).obj_id == obj_id){
                return objList.get(i);
            }
        }
        return null;
    }


}
