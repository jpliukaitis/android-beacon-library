package org.altbeacon.beacon;

import com.sensoro.beacon.kit.Beacon;
import com.sensoro.beacon.kit.SensoroUtils;

import java.math.BigDecimal;

public class SensoroUUID {
    public SensoroUUID() {
    }

    static String parseSN(byte[] sn) {
        String serialNumber = null;
        if (sn.length == 3) {
            serialNumber = "0117C5" + SensoroUtils.bytesToHex(sn);
        } else if (sn.length == 6) {
            serialNumber = SensoroUtils.bytesToHex(sn);
        }

        return serialNumber != null ? serialNumber.toUpperCase() : null;
    }

    static Integer parseTemperature(byte temperatureByte) {
        return temperatureByte == 255 ? null : temperatureByte - 10;
    }

    static Double parseBrightnessLux(byte luxHighByte, byte luxLowByte) {
        int luxRawHigh = luxHighByte & 255;
        int luxRawLow = luxLowByte & 255;
        return luxRawHigh == 255 ? null : calculateLux(luxRawHigh, luxRawLow);
    }

    private static double calculateLux(int luxRawHigh, int luxRawLow) {
        double light = Math.pow(2.0D, (double)(luxRawHigh / 16)) * (double)(luxRawHigh % 16 * 16 + luxRawLow % 16) * 0.045D;
        BigDecimal bigDecimal = (new BigDecimal(Double.toString(light))).setScale(3, 4);
        return bigDecimal.doubleValue();
    }

    public static int byteArrayToInt(byte[] b) {
        byte[] a = new byte[4];
        int i = a.length - 1;

        for(int j = b.length - 1; i >= 0; --j) {
            if (j >= 0) {
                a[i] = b[j];
            } else {
                a[i] = 0;
            }

            --i;
        }

        int v0 = (a[0] & 255) << 24;
        int v1 = (a[1] & 255) << 16;
        int v2 = (a[2] & 255) << 8;
        int v3 = a[3] & 255;
        return v0 + v1 + v2 + v3;
    }

    public static byte[] intToByteArray(int source, int length) {
        byte[] data = new byte[length];

        for(int i = 0; i < 4 && i < length; ++i) {
            data[i] = (byte)(source >> 8 * i & 255);
        }

        return data;
    }

    public static int byteArrayToInt(byte[] src, int offset) {
        int value = src[offset] & 255 | (src[offset + 1] & 255) << 8;
        return value;
    }
}
