package org.altbeacon.beacon;

class CRC8 {
    private static byte[] dscrc_table = new byte[256];

    private CRC8() {
    }

    public static int compute(int dataToCRC, int seed) {
        return dscrc_table[(seed ^ dataToCRC) & 255] & 255;
    }

    public static int compute(int dataToCRC) {
        return dscrc_table[dataToCRC & 255] & 255;
    }

    public static int compute(byte[] dataToCrc) {
        return compute(dataToCrc, 0, dataToCrc.length);
    }

    public static int compute(byte[] dataToCrc, int off, int len) {
        return compute(dataToCrc, off, len, 0);
    }

    public static int compute(byte[] dataToCrc, int off, int len, int seed) {
        int CRC8 = seed;

        for(int i = 0; i < len; ++i) {
            CRC8 = dscrc_table[(CRC8 ^ dataToCrc[i + off]) & 255];
        }

        return CRC8 & 255;
    }

    public static int compute(byte[] dataToCrc, int seed) {
        return compute(dataToCrc, 0, dataToCrc.length, seed);
    }

    static {
        for(int i = 0; i < 256; ++i) {
            int acc = i;
            int crc = 0;

            for(int j = 0; j < 8; ++j) {
                if (((acc ^ crc) & 1) == 1) {
                    crc = (crc ^ 24) >> 1 | 128;
                } else {
                    crc >>= 1;
                }

                acc >>= 1;
            }

            dscrc_table[i] = (byte)crc;
        }

    }
}
