package org.altbeacon.beacon;

import android.bluetooth.BluetoothDevice;
import android.os.ParcelUuid;
import com.android.scanner.BLEFilter;
import com.android.scanner.ScanBLEResult;
import com.sensoro.beacon.kit.Beacon.MovingState;
import android.os.ParcelUuid;
import com.android.scanner.BLEFilter;
import com.android.scanner.ScanBLEResult;
import com.sensoro.beacon.kit.Beacon.MovingState;
import com.sensoro.beacon.kit.constants.AdvertisingInterval;
import com.sensoro.beacon.kit.constants.EnergySavingMode;
import com.sensoro.beacon.kit.constants.TransmitPower;
import java.util.HashMap;
import java.util.Map;

class E781 extends SensoroUUID {
    private static final int MODE_1 = 16;
    private static final int MODE_2 = 32;
    private static final int MODE_3 = 48;
    private static final int MODE_4 = 64;
    private static final int MODE_41 = 65;
    private static final int MODE_42 = 66;
    private static final int MODE_5 = 80;
    private static final int RANDOM_CODE_LENGTH = 2;
    private static final int KEY_LENGTH = 14;
    private static final int KEY_ID_LENGTH = 2;
    private static final int DATA_START_INDEX = 0;
    private static final int DECRYPT_DATA_START_INDEX = 0;
    private static final String KEY_MAJOR = "major";
    private static final String KEY_MINOR = "minor";
    private static final String KEY_TEMPERATURE = "temperature";
    private static final String KEY_LIGNT = "light";
    private static final String KEY_ACCELEROMETERCOUNT = "accelerometerCount";
    private static final String KEY_MOVINGSTATE = "movingState";
    private static final String KEY_MEASUREPOWER = "measuredPower";
    private static HashMap<String, Integer> majorMap = new HashMap();
    private static HashMap<String, Integer> minorMap = new HashMap();
    private static HashMap<String, Integer> temperatureMap = new HashMap();
    private static HashMap<String, Double> lightMap = new HashMap();
    private static HashMap<String, Integer> accelerometerCountMap = new HashMap();
    private static HashMap<String, Integer> measuredPowerMap = new HashMap();
    String sn;
    String hardwareVersion;
    String firmwareVersion;
    int batteryLevel;
    TransmitPower transmitPower;
    AdvertisingInterval advertisingInterval;
    EnergySavingMode energySavingMode;
    boolean isPasswordEnabled;
    boolean isSecretEnabled;
    boolean isEnergySavingEnabled;
    boolean isAliBeaconEnabled;
    boolean isBackgroundEnhancementEnabled;
    boolean isEddystoneEnabled;
    boolean isEddystoneEIDEnable;
    boolean isEddystoneOnly;
    Integer major;
    Integer minor;
    int measuredPower;
    Integer temperature;
    Double light;
    int accelerometerCount;
    MovingState movingState;

    E781() {
        this.movingState = MovingState.UNKNOWN;
    }

    static E781 createE781(ScanBLEResult scanBLEResult, HashMap<String, byte[]> broadcastKeyMap) {
        Map<ParcelUuid, byte[]> serviceData = scanBLEResult.getScanRecord().getServiceData();
        if (serviceData == null) {
            return null;
        } else {
            ParcelUuid parcelUuid = BLEFilter.createServiceDataUUID("81E7");
            byte[] e781Bytes = scanBLEResult.getScanRecord().getServiceData(parcelUuid);
            return e781Bytes != null ? parseE781(e781Bytes, broadcastKeyMap) : null;
        }
    }

    private static E781 parseE781(byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        E781 e781 = new E781();
        int hardwareCode = e781Bytes[0] & 255;
        e781.hardwareVersion = Integer.toHexString(hardwareCode).toUpperCase();
        int firmwareCode = e781Bytes[1] & 255;
        e781.firmwareVersion = Integer.toHexString(firmwareCode / 16).toUpperCase() + "." + Integer.toHexString(firmwareCode % 16).toUpperCase();
        if (!VersionUtils.isSupportedFiremware(firmwareCode)) {
            return null;
        } else if (!VersionUtils.isSupportedHardware(hardwareCode)) {
            return null;
        } else {
            boolean parseResult = false;
            switch(e781Bytes[2] & 112) {
                case 16:
                    parseResult = parseMode1(e781, e781Bytes, broadcastKeyMap);
                    break;
                case 32:
                    parseResult = parseMode2(e781, e781Bytes, broadcastKeyMap);
                    break;
                case 48:
                    parseResult = parseMode3(e781, e781Bytes, broadcastKeyMap);
                    break;
                case 64:
                    parseResult = parseMode4(e781, e781Bytes, broadcastKeyMap);
                    break;
                case 80:
                    parseResult = parseMode5(e781, e781Bytes);
                    break;
                default:
                    return null;
            }

            return parseResult ? e781 : null;
        }
    }

    private static boolean isTheLastestVersion(int hardwareCode, int firmwareCode) {
        return hardwareCode <= 193 && firmwareCode <= 65;
    }

    private static boolean parseMode1(E781 e781, byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        byte[] sn;
        if ((e781Bytes[3] & 255) == 0 && (e781Bytes[4] & 255) == 0) {
            if (e781Bytes.length < 21) {
                return false;
            } else {
                sn = new byte[3];
                System.arraycopy(e781Bytes, 7, sn, 0, sn.length);
                e781.sn = parseSN(sn);
                e781.major = ((e781Bytes[13] & 255) << 8) + (e781Bytes[14] & 255);
                e781.minor = ((e781Bytes[15] & 255) << 8) + (e781Bytes[16] & 255);
                e781.batteryLevel = e781Bytes[17] & 255;
                E781.BitFields bitFields = parseBitFields(e781Bytes[18], e781Bytes[19]);
                e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
                e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
                e781.isPasswordEnabled = bitFields.isPasswordEnabled;
                e781.isSecretEnabled = bitFields.isSecretEnabled;
                e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
                e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
                e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
                e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
                e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
                e781.movingState = MovingState.DISABLED;
                e781.accelerometerCount = 0;
                e781.measuredPower = e781Bytes[20];
                return true;
            }
        } else {
            sn = new byte[2];
            System.arraycopy(e781Bytes, 3, sn, 0, sn.length);
            byte[] keyBytes = parseBroadcastKey(sn, broadcastKeyMap);
            if (keyBytes != null && keyBytes.length == 14) {
                byte[] encrypt = new byte[16];
                System.arraycopy(e781Bytes, 7, encrypt, 0, encrypt.length);
                byte[] key = new byte[16];
                System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
                System.arraycopy(e781Bytes, 5, key, 14, 2);
                byte[] decrypt = SensoroUtils.decrypt_AES_128(encrypt, key);
                byte[] snT = new byte[3];
                System.arraycopy(decrypt, 0, sn, 0, sn.length);
                e781.sn = parseSN(snT);
                e781.major = ((decrypt[6] & 255) << 8) + (decrypt[7] & 255);
                e781.minor = ((decrypt[8] & 255) << 8) + (decrypt[9] & 255);
                e781.batteryLevel = decrypt[10] & 255;
                E781.BitFields bitFields = parseBitFields(decrypt[11], decrypt[12]);
                e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
                e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
                e781.isPasswordEnabled = bitFields.isPasswordEnabled;
                e781.isSecretEnabled = bitFields.isSecretEnabled;
                e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
                e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
                e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
                e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
                e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
                e781.movingState = MovingState.DISABLED;
                e781.accelerometerCount = 0;
                e781.measuredPower = decrypt[13];
                int crc8 = CRC8.compute(sn);
                return (decrypt[15] & 255) == crc8;
            } else {
                return false;
            }
        }
    }

    private static boolean parseMode2(E781 e781, byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        byte[] keyIdBytes;
        if ((e781Bytes[3] & 255) == 0 && (e781Bytes[4] & 255) == 0) {
            keyIdBytes = new byte[3];
            System.arraycopy(e781Bytes, 7, keyIdBytes, 0, keyIdBytes.length);
            e781.sn = parseSN(keyIdBytes);
            e781.batteryLevel = e781Bytes[10] & 255;
            E781.BitFields bitFields = parseBitFields(e781Bytes[11], e781Bytes[12]);
            e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
            e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
            e781.isPasswordEnabled = bitFields.isPasswordEnabled;
            e781.isSecretEnabled = bitFields.isSecretEnabled;
            e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
            e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
            e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
            e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
            e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
            e781.temperature = parseTemperature(e781Bytes[13]);
            e781.light = parseBrightnessLux(e781Bytes[14], e781Bytes[15]);
            e781.accelerometerCount = (e781Bytes[16] & 255) + ((e781Bytes[17] & 255) << 8);
            e781.measuredPower = e781Bytes[19];
            return true;
        } else {
            keyIdBytes = new byte[2];
            System.arraycopy(e781Bytes, 3, keyIdBytes, 0, keyIdBytes.length);
            byte[] keyBytes = parseBroadcastKey(keyIdBytes, broadcastKeyMap);
            if (keyBytes != null && keyBytes.length == 14) {
                byte[] encrypt = new byte[16];
                System.arraycopy(e781Bytes, 7, encrypt, 0, encrypt.length);
                byte[] key = new byte[16];
                System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
                System.arraycopy(e781Bytes, 5, key, 14, 2);
                byte[] decrypt = SensoroUtils.decrypt_AES_128(encrypt, key);
                byte[] sn = new byte[3];
                System.arraycopy(decrypt, 0, sn, 0, sn.length);
                e781.sn = parseSN(sn);
                e781.batteryLevel = decrypt[3] & 255;
                E781.BitFields bitFields = parseBitFields(decrypt[4], decrypt[5]);
                e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
                e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
                e781.isPasswordEnabled = bitFields.isPasswordEnabled;
                e781.isSecretEnabled = bitFields.isSecretEnabled;
                e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
                e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
                e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
                e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
                e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
                e781.temperature = parseTemperature(decrypt[6]);
                e781.light = parseBrightnessLux(decrypt[7], decrypt[8]);
                e781.accelerometerCount = (decrypt[9] & 255) + ((decrypt[10] & 255) << 8);
                e781.measuredPower = decrypt[12];
                int crc8 = CRC8.compute(sn);
                return (decrypt[15] & 255) == crc8;
            } else {
                return false;
            }
        }
    }

    private static boolean parseMode3(E781 e781, byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        if (e781Bytes.length < 23) {
            return false;
        } else {
            byte[] sn = new byte[3];
            System.arraycopy(e781Bytes, 3, sn, 0, sn.length);
            e781.sn = parseSN(sn);
            e781.major = ((e781Bytes[9] & 255) << 8) + (e781Bytes[10] & 255);
            e781.minor = ((e781Bytes[11] & 255) << 8) + (e781Bytes[12] & 255);
            e781.batteryLevel = e781Bytes[13] & 255;
            E781.BitFields bitFields = parseBitFields(e781Bytes[14], e781Bytes[15]);
            e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
            e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
            e781.isPasswordEnabled = bitFields.isPasswordEnabled;
            e781.isSecretEnabled = bitFields.isSecretEnabled;
            e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
            e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
            e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
            e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
            e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
            e781.temperature = parseTemperature(e781Bytes[16]);
            e781.light = parseBrightnessLux(e781Bytes[17], e781Bytes[18]);
            e781.accelerometerCount = (e781Bytes[19] & 255) + ((e781Bytes[20] & 255) << 8);
            e781.measuredPower = e781Bytes[22];
            return true;
        }
    }

    private static boolean parseMode4(E781 e781, byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        if ((e781Bytes[2] & 255) == 65) {
            return parseMode41(e781, e781Bytes, broadcastKeyMap);
        } else {
            return (e781Bytes[2] & 255) == 66 ? parseMode42(e781, e781Bytes, broadcastKeyMap) : false;
        }
    }

    private static boolean parseMode5(E781 e781, byte[] e781Bytes) {
        e781.isEddystoneOnly = true;
        byte[] sn = new byte[3];
        System.arraycopy(e781Bytes, 3, sn, 0, sn.length);
        e781.sn = parseSN(sn);
        e781.batteryLevel = 255;
        return true;
    }

    private static boolean parseMode41(E781 e781, byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        if ((e781Bytes[3] & 255) == 0 && (e781Bytes[4] & 255) == 0) {
            return false;
        } else {
            byte[] keyIdBytes = new byte[2];
            System.arraycopy(e781Bytes, 3, keyIdBytes, 0, keyIdBytes.length);
            byte[] keyBytes = parseBroadcastKey(keyIdBytes, broadcastKeyMap);
            if (keyBytes != null && keyBytes.length == 14) {
                byte[] encrypt = new byte[16];
                System.arraycopy(e781Bytes, 7, encrypt, 0, encrypt.length);
                byte[] key = new byte[16];
                System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
                System.arraycopy(e781Bytes, 5, key, 14, 2);
                byte[] decrypt = SensoroUtils.decrypt_AES_128(encrypt, key);
                byte[] sn = new byte[3];
                System.arraycopy(decrypt, 0, sn, 0, sn.length);
                e781.sn = parseSN(sn);
                e781.major = ((decrypt[6] & 255) << 8) + (decrypt[7] & 255);
                e781.minor = ((decrypt[8] & 255) << 8) + (decrypt[9] & 255);
                e781.batteryLevel = decrypt[10] & 255;
                E781.BitFields bitFields = parseBitFields(decrypt[11], decrypt[12]);
                e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
                e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
                e781.isPasswordEnabled = bitFields.isPasswordEnabled;
                e781.isSecretEnabled = bitFields.isSecretEnabled;
                e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
                e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
                e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
                e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
                e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
                e781.temperature = (Integer)temperatureMap.get("temperature");
                e781.light = (Double)lightMap.get("light");
                if (accelerometerCountMap.get("accelerometerCount") != null) {
                    e781.accelerometerCount = (Integer)accelerometerCountMap.get("accelerometerCount");
                }

                if (measuredPowerMap.get("measuredPower") != null) {
                    e781.measuredPower = (Integer)measuredPowerMap.get("measuredPower");
                }

                majorMap.put("major", e781.major);
                minorMap.put("minor", e781.minor);
                int crc8 = CRC8.compute(sn);
                return (decrypt[15] & 255) == crc8;
            } else {
                return false;
            }
        }
    }

    private static boolean parseMode42(E781 e781, byte[] e781Bytes, HashMap<String, byte[]> broadcastKeyMap) {
        if ((e781Bytes[3] & 255) == 0 && (e781Bytes[4] & 255) == 0) {
            return false;
        } else {
            byte[] keyIdBytes = new byte[2];
            System.arraycopy(e781Bytes, 3, keyIdBytes, 0, keyIdBytes.length);
            byte[] keyBytes = parseBroadcastKey(keyIdBytes, broadcastKeyMap);
            if (keyBytes != null && keyBytes.length == 14) {
                byte[] encrypt = new byte[16];
                System.arraycopy(e781Bytes, 7, encrypt, 0, encrypt.length);
                byte[] key = new byte[16];
                System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
                System.arraycopy(e781Bytes, 5, key, 14, 2);
                byte[] decrypt = SensoroUtils.decrypt_AES_128(encrypt, key);
                byte[] sn = new byte[3];
                System.arraycopy(decrypt, 0, sn, 0, sn.length);
                e781.sn = parseSN(sn);
                e781.batteryLevel = decrypt[3] & 255;
                E781.BitFields bitFields = parseBitFields(decrypt[4], decrypt[5]);
                e781.transmitPower = TransmitPower.getTransmitPower(bitFields.transmitPower);
                e781.advertisingInterval = AdvertisingInterval.getAdvertisingInterval(bitFields.advertisingInterval);
                e781.isPasswordEnabled = bitFields.isPasswordEnabled;
                e781.isSecretEnabled = bitFields.isSecretEnabled;
                e781.isEnergySavingEnabled = bitFields.isEnergySavingEnabled;
                e781.isAliBeaconEnabled = bitFields.isAliBeaconEnabled;
                e781.isBackgroundEnhancementEnabled = bitFields.isBackgroundEnhancementEnabled;
                e781.isEddystoneEnabled = bitFields.isEddystoneEnabled;
                e781.energySavingMode = getEnergySavingMode(e781.isEnergySavingEnabled);
                e781.temperature = parseTemperature(decrypt[6]);
                e781.light = parseBrightnessLux(decrypt[7], decrypt[8]);
                e781.accelerometerCount = (decrypt[9] & 255) + ((decrypt[10] & 255) << 8);
                e781.measuredPower = decrypt[12];
                temperatureMap.put("temperature", e781.temperature);
                lightMap.put("light", e781.light);
                accelerometerCountMap.put("accelerometerCount", e781.accelerometerCount);
                measuredPowerMap.put("measuredPower", e781.measuredPower);
                if (majorMap.get("major") != null) {
                    e781.major = (Integer)majorMap.get("major");
                }

                if (minorMap.get("minor") != null) {
                    e781.minor = (Integer)minorMap.get("minor");
                }

                int crc8 = CRC8.compute(sn);
                return (decrypt[15] & 255) == crc8;
            } else {
                return false;
            }
        }
    }

    private static E781.BitFields parseBitFields(byte bitFieldsByteHigh, byte bitFieldsByteLow) {
        E781.BitFields bitFields = new E781.BitFields();
        bitFields.transmitPower = (bitFieldsByteHigh & 240) >> 4;
        bitFields.advertisingInterval = bitFieldsByteHigh & 15;
        bitFields.isPasswordEnabled = (bitFieldsByteLow & 128) != 0;
        bitFields.isSecretEnabled = (bitFieldsByteLow & 64) != 0;
        bitFields.isEnergySavingEnabled = (bitFieldsByteLow & 32) != 0;
        bitFields.isAliBeaconEnabled = (bitFieldsByteLow & 16) != 0;
        bitFields.isBackgroundEnhancementEnabled = (bitFieldsByteLow & 8) != 0;
        bitFields.isEddystoneEnabled = (bitFieldsByteLow & 4) != 0;
        return bitFields;
    }

    private static EnergySavingMode getEnergySavingMode(boolean isEnergySavingEnabled) {
        return isEnergySavingEnabled ? EnergySavingMode.LIGHT_SENSOR : EnergySavingMode.DISABLED;
    }

    private static byte[] parseBroadcastKey(byte[] keyIdBytes, HashMap<String, byte[]> broadcastKeyMap) {
        byte[] keyBytes = null;
        if (keyIdBytes.length != 2) {
            return null;
        } else {
            String keyId = SensoroUtils.bytesToHex(keyIdBytes);
            if (keyId != null && broadcastKeyMap != null) {
                keyBytes = (byte[])broadcastKeyMap.get(keyId.toLowerCase());
            }

            return keyBytes;
        }
    }

    static class BitFields {
        int transmitPower;
        int advertisingInterval;
        boolean isPasswordEnabled;
        boolean isSecretEnabled;
        boolean isEnergySavingEnabled;
        boolean isAliBeaconEnabled;
        boolean isBackgroundEnhancementEnabled;
        boolean isEddystoneEnabled;

        BitFields() {
        }
    }
}

