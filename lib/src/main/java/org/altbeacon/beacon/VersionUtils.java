package org.altbeacon.beacon;

import com.sensoro.beacon.kit.Beacon;

import java.util.Arrays;
import java.util.List;

public class VersionUtils {
    public static List<String> HW_NO_SENSOR = Arrays.asList("A0");
    public static List<String> HW_THREE_SENSOR = Arrays.asList("B0", "C0");
    public static List<String> HW_TWO_SENSOR = Arrays.asList("C1");
    public static String FV_EDDYSTONE_MINI = "4.0";
    public static String FV_PREVENT_TAMPER_MINI = "3.0";
    public static String FV_PREVENT_SQUATTER_MINI = "2.3";
    public static List<String> FV_EID = Arrays.asList("4.3", "4.4", "4.5", "4.6");
    static int[] supportFirmwareVersion = new int[]{16, 32, 33, 34, 35, 48, 49, 64, 65, 66, 67, 68, 69, 70};
    static int[] supportHardwareVersion = new int[]{160, 176, 192, 193, 200};

    public VersionUtils() {
    }

    public static boolean isSupportedFiremware(int firmwareVersion) {
        return Arrays.binarySearch(supportFirmwareVersion, firmwareVersion) != -1;
    }

    public static boolean isSupportedHardware(int hardwareVersion) {
        return Arrays.binarySearch(supportHardwareVersion, hardwareVersion) != -1;
    }

    public static boolean isAbove2_3(com.sensoro.beacon.kit.Beacon beacon) {
        int result = beacon.getFirmwareVersion().compareTo("2.3");
        return result >= 0;
    }

    public static boolean isSupportPreventTamper(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            String fw = beacon.getFirmwareVersion();
            int result = fw.compareTo(FV_PREVENT_TAMPER_MINI);
            return result >= 0;
        }
    }

    public static boolean isSupportPreventSquatter(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            String fw = beacon.getFirmwareVersion();
            int result = fw.compareTo(FV_PREVENT_SQUATTER_MINI);
            return result >= 0;
        }
    }

    public static boolean isSupportEnergySavingMode(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            return beacon.getHardwareModelName().equals("B0") && isAbove3_0(beacon);
        }
    }

    public static boolean isSupportInfoInBroadcast(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            return beacon.getHardwareModelName().equals("B0") && isAbove3_0(beacon);
        }
    }

    public static boolean isNoSensor(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            return HW_NO_SENSOR.contains(beacon.getHardwareModelName());
        }
    }

    public static boolean isSupportEID(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            return FV_EID.contains(beacon.getFirmwareVersion());
        }
    }

    public static boolean isTwoSensors(com.sensoro.beacon.kit.Beacon beacon) {
        if (beacon == null) {
            return false;
        } else {
            return HW_TWO_SENSOR.contains(beacon.getHardwareModelName());
        }
    }

    public static boolean isAbove3_0(com.sensoro.beacon.kit.Beacon beacon) {
        int result = beacon.getFirmwareVersion().compareTo("3.0");
        return result >= 0;
    }

    public static boolean isAbove3_1(com.sensoro.beacon.kit.Beacon beacon) {
        int result = beacon.getFirmwareVersion().compareTo("3.1");
        return result >= 0;
    }

    public static boolean isAbove4_0(Beacon beacon) {
        return beacon.getFirmwareVersion().compareTo("4.0") >= 0;
    }
}
