/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.bluetoothlegatt;

import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
;import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Service for managing connection and data communication with a GATT server hosted on a
 * given Bluetooth LE device.
 */
public class BluetoothLeService extends Service {
    private final static String TAG = BluetoothLeService.class.getSimpleName();

    private BluetoothManager mBluetoothManager;
    private BluetoothAdapter mBluetoothAdapter;
    private String mBluetoothDeviceAddress;
    private BluetoothGatt mBluetoothGatt;
    private int mConnectionState = STATE_DISCONNECTED;

    private Integer packetSize;
    private int packetInteration;
    private byte[][] packets;

    private String MacAddress = getBluetoothMacAddress();

    private ArrayList<AvailableObj> ObjList = new ArrayList<>();

    private static final int STATE_DISCONNECTED = 0;
    private static final int STATE_CONNECTING = 1;
    private static final int STATE_CONNECTED = 2;

    public final static String ACTION_GATT_CONNECTED = "com.example.bluetooth.le.ACTION_GATT_CONNECTED";
    public final static String ACTION_GATT_DISCONNECTED = "com.example.bluetooth.le.ACTION_GATT_DISCONNECTED";
    public final static String ACTION_GATT_SERVICES_DISCOVERED = "com.example.bluetooth.le.ACTION_GATT_SERVICES_DISCOVERED";
    public final static String ACTION_DATA_AVAILABLE = "com.example.bluetooth.le.ACTION_DATA_AVAILABLE";
    public final static String EXTRA_DATA = "com.example.bluetooth.le.EXTRA_DATA";

    /* Current Security Service UUID */
    public static UUID SECURITY_SERVICE = UUID.fromString("00001705-0000-1000-8000-00805f9b34fb");
    /* Mandatory Get Hello Accepted Msg Read Information Characteristic */
    public static UUID GET_HELLO_UUID = UUID.fromString("00002a2b-0000-1000-8000-00405f6b34cb");
    /* Mandatory Get Information about the real MacAddress of SmartObject */
    public static UUID GET_MAC_UUID = UUID.fromString("00002a2b-0000-1000-8000-00305f9b34fb");
    /* Mandatory Write Authentication Characteristic */
    public static UUID AUTH_WRITE_UUID = UUID.fromString("00000001-0000-1000-8000-00805f9b34fb");
    /* Mandatory Write My MacAddress Characteristic */
    public static UUID SET_MAC_UUID = UUID.fromString("00000001-0000-1000-8000-00605f9b34fb");
    /* Mandatory Read Information Characteristic */
    public static UUID READ_UUID = UUID.fromString("00002a2b-0000-1000-8000-00105f9b34fb");

    //Função que armazena a chave de sessão, o id do IoT e o OTP(One Time Password) no Database
    private boolean StoreKey(String obj_id_fix, String obj_id_random, SecretKeySpec Ksession, byte[] OTP, byte[] timestamp){
        int index = getIndex_IdFix(obj_id_fix);
        ObjList.get(index).setObj_id_random(obj_id_random);
        ObjList.get(index).setOTP(OTP);
        ObjList.get(index).setKsession(Ksession);
        ObjList.get(index).setTimestamp(timestamp);
        return true;
    }

    //Função que gera a mensagem criptografada ao ser enviada para o S-OBJ
    private byte[] GenerateHelloMessage(byte[] PackageK, byte[] Package_K_With_HMAC, byte[] ts){
        byte[] resp = new byte[PackageK.length + Package_K_With_HMAC.length + ts.length];
        System.arraycopy(PackageK, 0, resp, 0, PackageK.length);
        System.arraycopy(Package_K_With_HMAC, 0, resp, PackageK.length, Package_K_With_HMAC.length);
        System.arraycopy(ts, 0, resp, (PackageK.length + Package_K_With_HMAC.length), ts.length);
        return(resp);
    }

    //Função que gera o pacote da mensagem a ser enviada para o S-OBJ
    private byte[] GenerateHelloMessagePack(byte[] HelloMessage, byte[] HelloMessage_HMAC){
        byte[] resp = new byte[HelloMessage.length + HelloMessage_HMAC.length];
        System.arraycopy(HelloMessage, 0, resp, 0, HelloMessage.length);
        System.arraycopy(HelloMessage_HMAC, 0, resp, HelloMessage.length, HelloMessage_HMAC.length);
        return(resp);
    }

    //Função que gera a chave para gerar o HASH da mensagem HelloMessage
    private SecretKeySpec Generate_Hub_Auth_Key(byte[] OTP){
        SecretKeySpec Kauth_hub = new SecretKeySpec(OTP, "RC4");
        return Kauth_hub;
    }

    //Função que gera o hash do Hub_Id + A HelloMessage
    private byte[] GenerateHMAC(String hub_id, byte[] HM, SecretKeySpec Kauth_hub){
        byte[] Hello_Message_HMAC = new byte[0];
        String pack = null;
        try {
            pack = hub_id + new String(HM, "ASCII");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        Log.d(TAG, "Hub_ID:" + hub_id);
        Log.d(TAG, "HelloMessage:" + HM);
        Log.d(TAG, "PACK:" + pack);

        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_hub);

            Hello_Message_HMAC = mac.doFinal(pack.getBytes("ASCII"));

        } catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException ignored) {
        }

        return Hello_Message_HMAC;
    }

    //Função que gera o hash do Accepted Message
    private byte[] GenerateHMAC(String hub_id, String obj_id, byte[] Timestamp, SecretKeySpec Kauth_hub){
        byte[] Hello_Accepted_Message_HMAC = new byte[0];
        String pack = null;
        try {
            pack = hub_id + obj_id + new String(Timestamp, "ASCII");
            Log.d(TAG, "PACKKK: " + pack);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_hub);

            Hello_Accepted_Message_HMAC = mac.doFinal(pack.getBytes("ASCII"));

        } catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException e) {
        }

        return Hello_Accepted_Message_HMAC;
    }

    private byte[] signHelloMessage(String hub_id, byte[] OTP, byte [] HelloMessage){
        SecretKeySpec Kauth_hub = Generate_Hub_Auth_Key(OTP);
        return GenerateHMAC(hub_id, HelloMessage, Kauth_hub);
    }

    private String getBluetoothMacAddress() {
        BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        String bluetoothMacAddress = "";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M){
            try {
                Field mServiceField = bluetoothAdapter.getClass().getDeclaredField("mService");
                mServiceField.setAccessible(true);
                Object btManagerService = mServiceField.get(bluetoothAdapter);
                if (btManagerService != null) {
                    bluetoothMacAddress = (String) btManagerService.getClass().getMethod("getAddress").invoke(btManagerService);
                }
            } catch (NoSuchFieldException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
            }
        } else {
            bluetoothMacAddress = bluetoothAdapter.getAddress();
        }
        return bluetoothMacAddress;
    }

    private void SecureConnection(){
        getMacAddress();
    }

    private void checkAuth(String obj_id){
        Sddl sddl = new Sddl(obj_id, MacAddress);
        Package_Auth PACK = sddl.get_authorization(obj_id, MacAddress);

        if(PACK != null){
            Log.d(TAG, "PACK OTP length: " + PACK.OTP.length);
            Log.d(TAG, "PACK OTP: ");
            sddl.print_hex(PACK.OTP);

            Log.d(TAG, "PACK Ksession length: " + PACK.Ksession.getEncoded().length);
            Log.d(TAG, "PACK Ksession: ");
            sddl.print_hex(PACK.Ksession.getEncoded());

            Log.d(TAG, "PACK Package length: " + PACK.Package.length);
            Log.d(TAG, "PACK Package: ");
            sddl.print_hex(PACK.Package);

            Log.d(TAG, "PACK Package_HMAC length: " + PACK.Package_HMAC.length);
            Log.d(TAG, "PACK Package_HMAC: ");
            sddl.print_hex(PACK.Package_HMAC);

            int ts = (int)(System.currentTimeMillis());
            byte[] timestamp = ByteBuffer.allocate(4).putInt(ts).array();
            Log.d(TAG, "Timestamp: " + new java.util.Date(ByteBuffer.wrap(timestamp).getInt()));

            if(StoreKey(obj_id, mBluetoothDeviceAddress, PACK.Ksession, PACK.OTP, timestamp)){
                byte [] HelloMessage = GenerateHelloMessage(PACK.Package, PACK.Package_HMAC, timestamp);

                Log.d(TAG, "HelloMessage: ");
                sddl.print_hex(HelloMessage);

                byte [] HelloMessage_HMAC = signHelloMessage(MacAddress, PACK.OTP, HelloMessage);
                if(HelloMessage_HMAC!=null){
                    byte[] Pack_Auth = GenerateHelloMessagePack(HelloMessage, HelloMessage_HMAC);
                    Log.d(TAG, "Pack_Auth: ");
                    sddl.print_hex(Pack_Auth);
                    Log.d(TAG, "Pack_Auth Length: " + Pack_Auth.length);
                    Log.d(TAG, "HelloMessage: " + HelloMessage.length);
                    Log.d(TAG, "HelloMessage_HMAC: " + HelloMessage_HMAC.length);
                    Log.d(TAG, "HelloMessage_HMAC: ");
                    sddl.print_hex(HelloMessage_HMAC);

                    AuthCharacteristic(Pack_Auth);
                }
            }
        }
    }

    public void sendData(byte [] data, BluetoothGattCharacteristic Characteristic) {
        int chunksize = 20; //20 byte chunk
        packetSize = (int) Math.ceil(data.length / (double) chunksize); //make this variable public so we can access it on the other function

        packets = new byte[packetSize][chunksize];
        packetInteration = 0;
        Integer start = 0;
        for (int i = 0; i < packets.length; i++) {
            int end = start + chunksize;
            if (end > data.length) {
                end = data.length;
            }
            packets[i] = Arrays.copyOfRange(data, start, end);
            start += chunksize;
        }

        if (packetInteration < packetSize) {
            Log.d(TAG,"Enviando Pacote " + (packetInteration+1) + " de " + packetSize);
            Characteristic.setValue(packets[packetInteration]);
            mBluetoothGatt.writeCharacteristic(Characteristic);
            //mBluetoothGatt.executeReliableWrite();
            packetInteration++;
        }
    }

    private boolean RemoveObj(String ObjAddress){
        for(int i=0; i<ObjList.size(); i++){
            if(ObjList.get(i).getObj_id_random().equals(ObjAddress)){
                ObjList.remove(ObjList.get(i));
                return true;
            }
        }
        return false;
    }

    private int getIndex_IdFix(String ObjAddress){
        for(int i=0; i<ObjList.size(); i++){
            if(ObjList.get(i).getObj_id_fix().equals(ObjAddress)){
                return i;
            }
        }
        return 0;
    }

    private int getIndex_IdRandom(String ObjAddress){
        for(int i=0; i<ObjList.size(); i++){
            if(ObjList.get(i).getObj_id_random().equals(ObjAddress)){
                return i;
            }
        }
        return 0;
    }


    private boolean CheckSignForHelloAcceptedMessage(String hub_id, String obj_id, byte[] Timestamp, byte[] OTP, byte[] AcceptedHelloMsg_HASH){
        SecretKeySpec Kauth_hub = Generate_Hub_Auth_Key(OTP);
        byte[] AcceptedHelloMsg_HMAC = GenerateHMAC(hub_id, obj_id, Timestamp, Kauth_hub);
        Log.d(TAG, "AcceptedMessage_HASH: ");
        print_hex(AcceptedHelloMsg_HASH);

        Log.d(TAG, "AcceptedMessage_HMAC: ");
        print_hex(AcceptedHelloMsg_HMAC);

        if(Arrays.equals(AcceptedHelloMsg_HMAC, AcceptedHelloMsg_HASH)){
            return true;
        }
        return false;
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

    // Implements callback methods for GATT events that the app cares about.  For example,
    // connection change and services discovered.
    private final BluetoothGattCallback mGattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            String intentAction;
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                intentAction = ACTION_GATT_CONNECTED;
                mConnectionState = STATE_CONNECTED;
                broadcastUpdate(intentAction);
                Log.i(TAG, "Connected to GATT server.");
                // Attempts to discover services after successful connection.
                Log.i(TAG, "Attempting to start service discovery:" + mBluetoothGatt.discoverServices());

            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                intentAction = ACTION_GATT_DISCONNECTED;
                mConnectionState = STATE_DISCONNECTED;
                RemoveObj(gatt.getDevice().getAddress());
                Log.i(TAG, "Disconnected from GATT server.");
                broadcastUpdate(intentAction);
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                broadcastUpdate(ACTION_GATT_SERVICES_DISCOVERED);
                SecureConnection();
            } else {
                Log.w(TAG, "onServicesDiscovered received: " + status);
            }
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            if(characteristic.getUuid().equals(GET_MAC_UUID)){
                String objId = characteristic.getStringValue(0);
                ObjList.add(new AvailableObj(objId, mBluetoothDeviceAddress));
                sendMacAddress(MacAddress.getBytes());
            }else if(characteristic.getUuid().equals(GET_HELLO_UUID)){
                byte[] AcceptedHelloMsg = characteristic.getValue();
                int index = getIndex_IdRandom(gatt.getDevice().getAddress());
                if(CheckSignForHelloAcceptedMessage(MacAddress, ObjList.get(index).getObj_id_fix(), ObjList.get(index).getTimestamp(), ObjList.get(index).getOTP(), AcceptedHelloMsg)){
                    Log.d(TAG, "Estou autenticado!!!");
                }else{
                    Log.d(TAG, "Não estou autenticado T-T");
                }
            }else if (status == BluetoothGatt.GATT_SUCCESS) {
                int index = getIndex_IdRandom(gatt.getDevice().getAddress());
                broadcastUpdate(ACTION_DATA_AVAILABLE, characteristic, ObjList.get(index).getKsession());
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            //super.onCharacteristicWrite(gatt, characteristic, status);
            if(characteristic.getUuid().equals(AUTH_WRITE_UUID)){
                if(packetInteration == 3){
                    Log.d(TAG, "Get Hello Message!!!");
                    getHelloAcceptedMessage();
                }
                if(packetInteration < packetSize){
                    Log.d(TAG,"Enviando Pacote " + (packetInteration+1) + " de " + packetSize);
                    characteristic.setValue(packets[packetInteration]);
                    mBluetoothGatt.writeCharacteristic(characteristic);
                    packetInteration++;
                }
            }
            if(characteristic.getUuid().equals(SET_MAC_UUID)){
                for(int i=0; i<ObjList.size(); i++) {
                    if(mBluetoothDeviceAddress.equals(ObjList.get(i).getObj_id_random())){
                        checkAuth(ObjList.get(i).getObj_id_fix());
                    }
                }
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
            broadcastUpdate(ACTION_DATA_AVAILABLE, characteristic);
        }
    };

    private void broadcastUpdate(final String action) {
        final Intent intent = new Intent(action);
        sendBroadcast(intent);
    }

    private void broadcastUpdate(final String action, final BluetoothGattCharacteristic characteristic) {
        final Intent intent = new Intent(action);
        // Broadcast the information of a characteristic.
        intent.putExtra(EXTRA_DATA, characteristic.getValue());
        sendBroadcast(intent);
    }

    private void broadcastUpdate(final String action, final BluetoothGattCharacteristic characteristic, SecretKeySpec Ksession) {
        final Intent intent = new Intent(action);
        // Broadcast the information of a characteristic.
        byte[] text = null;
        try {
            text = ClientSecurityClass.Decrypt(characteristic.getValue(), Ksession);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        intent.putExtra(EXTRA_DATA, text);
        sendBroadcast(intent);
    }

//    private void broadcastUpdate(final String action, final BluetoothGattCharacteristic characteristic, String ObjAddress) {
//        final Intent intent = new Intent(action);
//        // Broadcast the information of a characteristic.
//        intent.putExtra(EXTRA_DATA, characteristic.getValue());
//        sendBroadcast(intent);
//        if(characteristic.getUuid().equals(GET_MAC_UUID)){
//            String objId = characteristic.getStringValue(0);
//            ObjList.add(new AvailableObj(objId));
//            checkAuth(objId);
//        }else if(characteristic.getUuid().equals(GET_HELLO_UUID)){
//            byte[] AcceptedHelloMsg = characteristic.getValue();
//            int index = getIndex_IdRandom(ObjAddress);
//            if(CheckSignForHelloAcceptedMessage(mBluetoothAdapter.getAddress(), ObjList.get(index).getObj_id_fix(), ObjList.get(index).getTimestamp(), ObjList.get(index).getOTP(), AcceptedHelloMsg)){
//                Log.d(TAG, "Estou autenticado!!!");
//            }else{
//                Log.d(TAG, "Não estou autenticado T-T");
//            }
//        }
//    }

    public class LocalBinder extends Binder {
        BluetoothLeService getService() {
            return BluetoothLeService.this;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    @Override
    public boolean onUnbind(Intent intent) {
        // After using a given device, you should make sure that BluetoothGatt.close() is called
        // such that resources are cleaned up properly.  In this particular example, close() is
        // invoked when the UI is disconnected from the Service.
        close();
        return super.onUnbind(intent);
    }

    private final IBinder mBinder = new LocalBinder();

    /**
     * Initializes a reference to the local Bluetooth adapter.
     *
     * @return Return true if the initialization is successful.
     */
    public boolean initialize() {
        // For API level 18 and above, get a reference to BluetoothAdapter through
        // BluetoothManager.
        if (mBluetoothManager == null) {
            mBluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
            if (mBluetoothManager == null) {
                Log.e(TAG, "Unable to initialize BluetoothManager.");
                return false;
            }
        }

        mBluetoothAdapter = mBluetoothManager.getAdapter();
        if (mBluetoothAdapter == null) {
            Log.e(TAG, "Unable to obtain a BluetoothAdapter.");
            return false;
        }

        return true;
    }

    /**
     * Connects to the GATT server hosted on the Bluetooth LE device.
     *
     * @param address The device address of the destination device.
     *
     * @return Return true if the connection is initiated successfully. The connection result
     *         is reported asynchronously through the
     *         {@code BluetoothGattCallback#onConnectionStateChange(android.bluetooth.BluetoothGatt, int, int)}
     *         callback.
     */
    public boolean connect(final String address) {
        if (mBluetoothAdapter == null || address == null) {
            Log.w(TAG, "BluetoothAdapter not initialized or unspecified address.");
            return false;
        }

        // Previously connected device.  Try to reconnect.
        if (mBluetoothDeviceAddress != null && address.equals(mBluetoothDeviceAddress) && mBluetoothGatt != null) {
            Log.d(TAG, "Trying to use an existing mBluetoothGatt for connection.");
            if (mBluetoothGatt.connect()) {
                mConnectionState = STATE_CONNECTING;
                return true;
            } else {
                return false;
            }
        }

        final BluetoothDevice device = mBluetoothAdapter.getRemoteDevice(address);
        if (device == null) {
            Log.w(TAG, "Device not found.  Unable to connect.");
            return false;
        }
        // We want to directly connect to the device, so we are setting the autoConnect
        // parameter to false.
        mBluetoothGatt = device.connectGatt(this, false, mGattCallback);
        Log.d(TAG, "Trying to create a new connection.");
        mBluetoothDeviceAddress = address;
        mConnectionState = STATE_CONNECTING;
        return true;
    }

    /**
     * Disconnects an existing connection or cancel a pending connection. The disconnection result
     * is reported asynchronously through the
     * {@code BluetoothGattCallback#onConnectionStateChange(android.bluetooth.BluetoothGatt, int, int)}
     * callback.
     */
    public void disconnect() {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        mBluetoothGatt.disconnect();
    }

    /**
     * After using a given BLE device, the app must call this method to ensure resources are
     * released properly.
     */
    public void close() {
        if (mBluetoothGatt == null) {
            return;
        }
        mBluetoothGatt.close();
        mBluetoothGatt = null;
    }

    /**
     * Request a read on a given {@code BluetoothGattCharacteristic}. The read result is reported
     * asynchronously through the {@code BluetoothGattCallback#onCharacteristicRead(android.bluetooth.BluetoothGatt, android.bluetooth.BluetoothGattCharacteristic, int)}
     * callback.
     *
     * @param characteristic The characteristic to read from.
     */
    public void readCharacteristic(BluetoothGattCharacteristic characteristic) {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        mBluetoothGatt.readCharacteristic(characteristic);
    }

    /**
     * Retrieves a list of supported GATT services on the connected device. This should be
     * invoked only after {@code BluetoothGatt#discoverServices()} completes successfully.
     *
     * @return A {@code List} of supported services.
     */
    public List<BluetoothGattService> getSupportedGattServices() {
        if (mBluetoothGatt == null)
            return null;
        return mBluetoothGatt.getServices();
    }

    public void getHelloAcceptedMessage() {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mSecurityService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mSecurityService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }

        /*get the read characteristic from the service*/
        BluetoothGattCharacteristic mReadCharacteristic = mSecurityService.getCharacteristic(GET_HELLO_UUID);
        if(!mBluetoothGatt.readCharacteristic(mReadCharacteristic)){
            Log.w(TAG, "Failed to read characteristic");
        }
    }

    public void getMacAddress() {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mSecurityService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mSecurityService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }

        /*get the read characteristic from the service*/
        BluetoothGattCharacteristic mReadCharacteristic = mSecurityService.getCharacteristic(GET_MAC_UUID);
        if(!mBluetoothGatt.readCharacteristic(mReadCharacteristic)){
            Log.w(TAG, "Failed to read characteristic");
        }
    }

    public void readCustomCharacteristic() {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mSecurityService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mSecurityService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }

        /*get the read characteristic from the service*/
        BluetoothGattCharacteristic mReadCharacteristic = mSecurityService.getCharacteristic(READ_UUID);
        if(!mBluetoothGatt.readCharacteristic(mReadCharacteristic)){
            Log.w(TAG, "Failed to read characteristic");
        }
    }

    public void AuthCharacteristic(byte[] value) {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mSecurityService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mSecurityService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }
        /*get the write characteristic from the service*/
        BluetoothGattCharacteristic mWriteCharacteristic = mSecurityService.getCharacteristic(AUTH_WRITE_UUID);
        if (value != null) {
            sendData(value, mWriteCharacteristic);
            //mWriteCharacteristic.setValue(value);
        }
        //if(!mBluetoothGatt.writeCharacteristic(mWriteCharacteristic)){
        //    Log.w(TAG, "Failed to write characteristic");
        //}
    }

    public void sendMacAddress(byte[] value) {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mSecurityService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mSecurityService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }
        /*get the write characteristic from the service*/
        BluetoothGattCharacteristic mWriteCharacteristic = mSecurityService.getCharacteristic(SET_MAC_UUID);
        if (value != null) {
            Log.d(TAG, "Sending MacAddress");
            mWriteCharacteristic.setValue(value);
            if (!mBluetoothGatt.writeCharacteristic(mWriteCharacteristic)) {
                Log.w(TAG, "Failed to write characteristic");
            }
        } else {
            Log.w(TAG, "Failed to write characteristic - Value is equal NULL");
        }
        return;
    }
}
