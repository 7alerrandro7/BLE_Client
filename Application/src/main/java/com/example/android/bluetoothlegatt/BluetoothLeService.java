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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;;import javax.crypto.Mac;
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
    public static UUID SECURITY_SERVICE = UUID.fromString("00001805-0000-1000-8000-00805f9b34fb");
    /* Mandatory Read Information Characteristic */
    public static UUID CHARACTERISTIC_READ_UUID = UUID.fromString("00002a2b-0000-1000-8000-00805f9b34fb");
    /* Mandatory Write Information Characteristic */
    public static UUID AUTH_WRITE_UUID = UUID.fromString("00000001-0000-1000-8000-00805f9b34fb");

    //Função que armazena a chave de sessão, o id do IoT e o OTP(One Time Password) no Database
    private boolean StoreKey(String obj_id, SecretKeySpec Ksession, byte[] OTP){
        ObjList.add(new AvailableObj(obj_id, Ksession, OTP));
        if(!ObjList.isEmpty()){
            return true;
        }
        return false;
    }

    //Função que gera a mensagem criptografada ao ser enviada para o S-OBJ
    private byte[] GenerateHelloMessage(byte[] PackageK, byte[] Package_K_With_HMAC, byte[] ts){
        byte[] resp = new byte[PackageK.length + Package_K_With_HMAC.length + ts.length];
        System.arraycopy(PackageK, 0, resp, 0, PackageK.length);
        System.arraycopy(Package_K_With_HMAC, 0, resp, PackageK.length, Package_K_With_HMAC.length);
        System.arraycopy(ts, 0, resp, PackageK.length + Package_K_With_HMAC.length, ts.length);
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
        String pack = hub_id + HM;

        try {
            Mac mac = Mac.getInstance("hmacMD5");
            mac.init(Kauth_hub);

            Hello_Message_HMAC = mac.doFinal(pack.getBytes("ASCII"));

        } catch (UnsupportedEncodingException e) {
        } catch (InvalidKeyException e) {
        } catch (NoSuchAlgorithmException e) {
        }

        return Hello_Message_HMAC;
    }

    private byte[] signHelloMessage(String hub_id, byte[] OTP, byte [] HelloMessage){
        SecretKeySpec Kauth_hub = Generate_Hub_Auth_Key(OTP);
        byte[] Hello_Message_HMAC = GenerateHMAC(hub_id, HelloMessage, Kauth_hub);
        return Hello_Message_HMAC;
    }


    private void SecureConnection(){
        Sddl sddl = new Sddl(mBluetoothDeviceAddress,  mBluetoothAdapter.getAddress());
        Package_Auth PACK = sddl.get_authorization(mBluetoothDeviceAddress, mBluetoothAdapter.getAddress());

        if(PACK != null){
            Log.d(TAG, "PACK OTP: " + PACK.OTP);
            sddl.print_hex(PACK.OTP);
            Log.d(TAG, "PACK Ksession: " + PACK.Ksession);

            Log.d(TAG, "PACK Package: " + PACK.Package.length);
            Log.d(TAG, "PACK Package_HMAC: " + PACK.Package_HMAC.length);

            Log.d(TAG, "PACK Package: ");
            sddl.print_hex(PACK.Package);
            Log.d(TAG, "PACK Package_HMAC: ");
            sddl.print_hex(PACK.Package_HMAC);

            if(StoreKey(mBluetoothDeviceAddress, PACK.Ksession, PACK.OTP)){
                int ts = (int)(System.currentTimeMillis());
                byte[] timestamp = ByteBuffer.allocate(4).putInt(ts).array();
                byte [] HelloMessage = GenerateHelloMessage(PACK.Package, PACK.Package_HMAC, timestamp);

                Log.d(TAG, "HelloMessage: ");
                sddl.print_hex(HelloMessage);

                byte [] HelloMessage_HMAC = signHelloMessage(mBluetoothAdapter.getAddress(), PACK.OTP, HelloMessage);
                if(HelloMessage_HMAC!=null){
                    byte[] Pack_Auth = GenerateHelloMessagePack(HelloMessage, HelloMessage_HMAC);
                    Log.d(TAG, "Pack_Auth: ");
                    sddl.print_hex(Pack_Auth);
                    Log.d(TAG, "Pack_Auth Length: " + Pack_Auth.length);
                    Log.d(TAG, "HelloMessage: " + HelloMessage.length);
                    Log.d(TAG, "HelloMessage_HMAC: " + HelloMessage_HMAC.length);
                    Log.d(TAG, "HelloMessage_HMAC: ");
                    sddl.print_hex(HelloMessage_HMAC);

                    writeCustomCharacteristic(Pack_Auth);
                }
            }
        }

        return;
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

    private Object convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInput in = new ObjectInputStream(bis)) {
            return in.readObject();
        }
    }

    public void sendData(byte [] data, BluetoothGattCharacteristic writeC) {
        int chunksize = 20; //20 byte chunk
        packetSize = (int) Math.ceil(data.length / (double) chunksize); //make this variable public so we can access it on the other function

        //Log.d(TAG, "LENGTH: " + Integer.toString(data.length));
        //this is use as header, so peripheral device know ho much packet will be received.
        /*
        writeC.setValue(Integer.toString(data.length).getBytes());
        Log.d(TAG, "TAM: " + Integer.toString(data.length).getBytes());
        Log.d(TAG, "TAM: " + Integer.toString(data.length).getBytes().length);
        mBluetoothGatt.writeCharacteristic(writeC);
        mBluetoothGatt.executeReliableWrite();
        */

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

        //if(writeC.getUuid().equals(AUTH_WRITE_UUID)) {
            //for (int i = 0; i<packetSize; i++) {
                //Log.d(TAG, "I: " + i + "  -- Packetsize: " + packetSize);
                if (packetInteration < packetSize) {
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    writeC.setValue(packets[packetInteration]);
                    mBluetoothGatt.writeCharacteristic(writeC);
                    mBluetoothGatt.executeReliableWrite();
                    packetInteration++;
                }
            //}
        //}
    }

    // Implements callback methods for GATT events that the app cares about.  For example,
    // connection change and services discovered.
    private final BluetoothGattCallback mGattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            String intentAction;
            Log.d(TAG, "NEWSTATE: " + newState);
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
            if (status == BluetoothGatt.GATT_SUCCESS) {
                broadcastUpdate(ACTION_DATA_AVAILABLE, characteristic);
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            //super.onCharacteristicWrite(gatt, characteristic, status);

            if(characteristic.getUuid().equals(AUTH_WRITE_UUID)){
                if(packetInteration < packetSize){
                    characteristic.setValue(packets[packetInteration]);
                    mBluetoothGatt.writeCharacteristic(characteristic);
                    packetInteration++;
                }
            }else{
                super.onCharacteristicWrite(gatt, characteristic, status);
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

    public void readCustomCharacteristic() {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mCustomService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mCustomService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }

        /*get the read characteristic from the service*/
        BluetoothGattCharacteristic mReadCharacteristic = mCustomService.getCharacteristic(CHARACTERISTIC_READ_UUID);
        if(!mBluetoothGatt.readCharacteristic(mReadCharacteristic)){
            Log.w(TAG, "Failed to read characteristic");
        }
    }

    public void writeCustomCharacteristic(byte[] value) {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        /*check if the service is available on the device*/
        BluetoothGattService mCustomService = mBluetoothGatt.getService(SECURITY_SERVICE);
        if(mCustomService == null){
            Log.w(TAG, "Custom BLE Service not found");
            return;
        }
        /*get the write characteristic from the service*/
        BluetoothGattCharacteristic mWriteCharacteristic = mCustomService.getCharacteristic(AUTH_WRITE_UUID);
        if (value != null) {
            sendData(value, mWriteCharacteristic);
            //mWriteCharacteristic.setValue(value);
        }
        //if(!mBluetoothGatt.writeCharacteristic(mWriteCharacteristic)){
        //    Log.w(TAG, "Failed to write characteristic");
        //}
    }
}
