package org.altbeacon.beacon;

import android.os.Parcel;

import static android.test.MoreAsserts.assertNotEqual;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.robolectric.RobolectricTestRunner;

import org.junit.runner.RunWith;
import org.junit.Test;

@RunWith(RobolectricTestRunner.class)

/*
HOW TO SEE DEBUG LINES FROM YOUR UNIT TESTS:

1. set a line like this at the start of your test:
           org.robolectric.shadows.ShadowLog.stream = System.err;
2. run the tests from the command line
3. Look at the test report file in your web browser, e.g.
   file:///Users/dyoung/workspace/AndroidProximityLibrary/build/reports/tests/index.html
4. Expand the System.err section
 */
public class AltBeaconParserTest {

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    @Test
    public void testRecognizeBeacon() {
        byte[] bytes = hexStringToByteArray("02011a1affacbe2f234454cf6d4a0fadf2f4911ba9ffa600010002c509");
        AltBeaconParser parser = new AltBeaconParser();
        Beacon beacon = parser.fromScanData(bytes, -55, null);
        assertEquals("mRssi should be as passed in", -55, beacon.getRssi());
        assertEquals("uuid should be parsed", "2f234454-cf6d-4a0f-adf2-f4911ba9ffa6", beacon.getIdentifier(1).toString());
        assertEquals("id2 should be parsed", "1", beacon.getIdentifier(2).toString());
        assertEquals("id3 should be parsed", "2", beacon.getIdentifier(3).toString());
        assertEquals("manData should be parsed", 9, ((AltBeacon) beacon).getManData() );
    }

    @Test
    public void testHardwareDetection() {
        BeaconManager.debug = true;
        org.robolectric.shadows.ShadowLog.stream = System.err;
        byte[] bytes = hexStringToByteArray("02011a1bff1801acbe2f234454cf6d4a0fadf2f4911ba9ffa600050003be020e09526164426561636f6e20555342020a0300000000000000000000000000");
        AltBeaconParser parser = new AltBeaconParser();
        Beacon beacon = parser.fromScanData(bytes, -55, null);
        assertNotNull("Beacon should be not null if parsed successfully", beacon);
    }
}
