package org.altbeacon.beacon;

import android.util.Base64;
import android.util.Log;
import android.util.SparseArray;
import android.webkit.URLUtil;
import com.sensoro.beacon.kit.Beacon.Proximity;
import com.sensoro.beacon.kit.constants.SecureBroadcastInterval;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SensoroUtils {
    private static final char[] HEX_CHAR_TABLE = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final SparseArray<String> URI_SCHEMES = new SparseArray<String>() {
        {
            this.put(0, "http://www.");
            this.put(1, "https://www.");
            this.put(2, "http://");
            this.put(3, "https://");
            this.put(4, "urn:uuid:");
        }
    };
    private static final SparseArray<String> URL_CODES = new SparseArray<String>() {
        {
            this.put(0, ".com/");
            this.put(1, ".org/");
            this.put(2, ".edu/");
            this.put(3, ".net/");
            this.put(4, ".info/");
            this.put(5, ".biz/");
            this.put(6, ".gov/");
            this.put(7, ".com");
            this.put(8, ".org");
            this.put(9, ".edu");
            this.put(10, ".net");
            this.put(11, ".info");
            this.put(12, ".biz");
            this.put(13, ".gov");
        }
    };
    private static final int FIVE_SECONDS = 5;
    private static final int ONE_MINUTE = 60;
    private static final int ONE_HOUR = 3600;
    private static final int ONE_DAY = 86400;
    private static final int SEVEN_DAYS = 604800;
    private static final int THIRTY_DAYS = 2592000;

    public SensoroUtils() {
    }

    public static int getSecureBroadcastIntervalInt(SecureBroadcastInterval secureBroadcastInterval) {
        switch(secureBroadcastInterval) {
            case UNKNOWN:
                return 0;
            case DISABLED:
                return 0;
            case SECURE_BROADCAST_INTERVAL_5_SECONDS:
                return 5;
            case SECURE_BROADCAST_INTERVAL_1_MINTE:
                return 60;
            case SECURE_BROADCAST_INTERVAL_1_HONR:
                return 3600;
            case SECURE_BROADCAST_INTERVAL_1_DAY:
                return 86400;
            case SECURE_BROADCAST_INTERVAL_7_DAYS:
                return 604800;
            case SECURE_BROADCAST_INTERVAL_30_DAYS:
                return 2592000;
            default:
                return 0;
        }
    }

    public static SecureBroadcastInterval getSecureBroadcastInterval(int secureBroadcastIntervalInt) {
        switch(secureBroadcastIntervalInt) {
            case 0:
                return SecureBroadcastInterval.DISABLED;
            case 5:
                return SecureBroadcastInterval.SECURE_BROADCAST_INTERVAL_5_SECONDS;
            case 60:
                return SecureBroadcastInterval.SECURE_BROADCAST_INTERVAL_1_MINTE;
            case 3600:
                return SecureBroadcastInterval.SECURE_BROADCAST_INTERVAL_1_HONR;
            case 86400:
                return SecureBroadcastInterval.SECURE_BROADCAST_INTERVAL_1_DAY;
            case 604800:
                return SecureBroadcastInterval.SECURE_BROADCAST_INTERVAL_7_DAYS;
            case 2592000:
                return SecureBroadcastInterval.SECURE_BROADCAST_INTERVAL_30_DAYS;
            default:
                return SecureBroadcastInterval.UNKNOWN;
        }
    }

    public static byte[] convertUUIDToBytes(String uuid) {
        uuid = uuid.replace("-", "");
        byte[] uuidBytes = HexString2Bytes(uuid);
        return uuidBytes;
    }

    public static ArrayList<byte[]> parseBytes2ByteList(byte[] bytes) {
        ArrayList<byte[]> byteList = null;
        if (bytes != null) {
            byteList = new ArrayList();

            for(int i = 0; i < bytes.length; ++i) {
                int length = bytes[i] & 255;
                if (length == 0) {
                    return byteList;
                }

                byte[] byteData = new byte[length + 1];
                System.arraycopy(bytes, i, byteData, 0, length + 1);
                byteList.add(byteData);
                i += length;
            }
        }

        return byteList;
    }

    public static byte[] encodeUrl(String url) {
        int i;
        for(i = 0; i < URI_SCHEMES.size(); ++i) {
            if (url.startsWith((String)URI_SCHEMES.get(i))) {
                url = url.replace((CharSequence)URI_SCHEMES.get(i), String.valueOf((char)((byte)i)));
            }
        }

        for(i = 0; i < URL_CODES.size(); ++i) {
            url = url.replace((CharSequence)URL_CODES.get(i), String.valueOf((char)((byte)i)));
        }

        byte[] bytes = new byte[url.length()];

        for(int k = 0; k < url.length(); ++k) {
            bytes[k] = (byte)url.charAt(k);
        }

        return bytes;
    }

    public static String decodeUrl(byte[] urlBytes) {
        StringBuilder url = new StringBuilder();
        byte offset = 0;

        try {
            byte var10001 = offset;
            int offset1 = offset + 1;
            byte b = urlBytes[var10001];
            String scheme = (String)URI_SCHEMES.get(b);
            if (scheme != null) {
                url.append(scheme);
                if (URLUtil.isNetworkUrl(scheme)) {
                    return decodeUrl(urlBytes, offset1, url);
                }
            }

            return url.toString();
        } catch (Exception var5) {
            return null;
        }
    }

    private static String decodeUrl(byte[] serviceData, int offset, StringBuilder urlBuilder) {
        while(offset < serviceData.length) {
            byte b = serviceData[offset++];
            String code = (String)URL_CODES.get(b);
            if (code != null) {
                urlBuilder.append(code);
            } else {
                urlBuilder.append((char)b);
            }
        }

        return urlBuilder.toString();
    }

    public static byte[] HexString2Bytes(String src) {
        int length = src.length() / 2;
        byte[] ret = new byte[length];
        byte[] tmp = src.getBytes();

        for(int i = 0; i < length; ++i) {
            ret[i] = uniteBytes(tmp[i * 2], tmp[i * 2 + 1]);
        }

        return ret;
    }

    public static byte uniteBytes(byte src0, byte src1) {
        byte _b0 = Byte.decode("0x" + new String(new byte[]{src0}));
        _b0 = (byte)(_b0 << 4);
        byte _b1 = Byte.decode("0x" + new String(new byte[]{src1}));
        byte ret = (byte)(_b0 ^ _b1);
        return ret;
    }

    public static byte[] HMacSHA512(byte[] data, String passwordKey) {
        byte[] secretBytes = passwordKey.getBytes();
        byte[] signatureBytes = null;

        try {
            Mac shaMac = Mac.getInstance("HmacSHA512");
            SecretKey secretKey = new SecretKeySpec(secretBytes, "HmacSHA512");
            shaMac.init(secretKey);
            signatureBytes = shaMac.doFinal(data);
        } catch (InvalidKeyException var6) {
            var6.printStackTrace();
        } catch (NoSuchAlgorithmException var7) {
            var7.printStackTrace();
        }

        return signatureBytes;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];

        for(int j = 0; j < bytes.length; ++j) {
            int v = bytes[j] & 255;
            hexChars[j * 2] = HEX_CHAR_TABLE[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHAR_TABLE[v & 15];
        }

        return (new String(hexChars)).toUpperCase();
    }

    public static int getHexCharValue(char c) {
        int index = 0;
        char[] var2 = HEX_CHAR_TABLE;
        int var3 = var2.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            char c1 = var2[var4];
            if (c == c1) {
                return index;
            }

            ++index;
        }

        return 0;
    }

    public static byte[] decrypt_AES_128(byte[] src, byte[] key) {
        byte[] original = null;
        if (key == null) {
            return null;
        } else if (key.length != 16) {
            return null;
        } else {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(2, skeySpec);
                original = cipher.doFinal(src);
                return original;
            } catch (Exception var5) {
                return null;
            }
        }
    }

    public static String decrypt_AES_256(String src, String key) {
        if (key == null) {
            return null;
        } else if (src == null) {
            return null;
        } else {
            try {
                SecretKey secretKey = getKey(key);
                byte[] iv = new byte[16];
                Arrays.fill(iv, (byte)0);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                byte[] encrypedPwdBytes = Base64.decode(src, 0);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                cipher.init(2, secretKey, ivParameterSpec);
                byte[] decrypedValueBytes = cipher.doFinal(encrypedPwdBytes);
                String decrypedValue = new String(decrypedValueBytes);
                return decrypedValue;
            } catch (Exception var9) {
                return null;
            }
        }
    }

    public static byte[] encrypt(byte[] key, byte[] src) throws Exception {
        byte[] rawKey = getRawKey(key);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(1, skeySpec);
        byte[] encrypted = cipher.doFinal(src);
        return encrypted;
    }

    private static byte[] getRawKey(byte[] seed) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        kgen.init(128, sr);
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        return raw;
    }

    private static SecretKeySpec getKey(String password) throws UnsupportedEncodingException {
        int keyLength = 256;
        byte[] keyBytes = new byte[keyLength / 8];
        Arrays.fill(keyBytes, (byte)0);
        byte[] passwordBytes = password.getBytes("UTF-8");
        int length = passwordBytes.length < keyBytes.length ? passwordBytes.length : keyBytes.length;
        System.arraycopy(passwordBytes, 0, keyBytes, 0, length);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        return key;
    }

    public static double calculateAccuracy(int txPower, double rssi) {
        if (txPower != 0 && txPower != 2147483647) {
            if (rssi == 0.0D) {
                return -1.0D;
            } else {
                double accuracy = 0.0D;
                double ratio = rssi * 1.0D / (double)txPower;
                if (ratio < 1.0D) {
                    accuracy = Math.pow(ratio, 10.0D);
                } else {
                    accuracy = 0.89976D * Math.pow(ratio, 7.7095D) + 0.111D;
                }

                return (new BigDecimal(Double.toString(accuracy))).setScale(4, 4).doubleValue();
            }
        } else {
            Log.v("", "");
            return -1.0D;
        }
    }

    public static Proximity calculateProximity(double accuracy) {
        if (accuracy < 0.0D) {
            return Proximity.PROXIMITY_UNKNOWN;
        } else if (accuracy < 0.5D) {
            return Proximity.PROXIMITY_IMMEDIATE;
        } else {
            return accuracy <= 4.0D ? Proximity.PROXIMITY_NEAR : Proximity.PROXIMITY_FAR;
        }
    }

    public static String parseEddystoneURL(byte[] eddystoneURLBytes) {
        String url = null;
        return (String)url;
    }

    public static <T> T checkNotNull(T reference, Object errorMessage) {
        if (reference == null) {
            throw new NullPointerException(String.valueOf(errorMessage));
        } else {
            return reference;
        }
    }
}
