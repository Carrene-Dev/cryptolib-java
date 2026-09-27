package cryptolib;

import org.apache.commons.codec.binary.Hex;

public class PinBlockApp {

    public static void main(String[] args) {
        String pin = "1234";
        String pan = "6037997390214444";
        String desSeed = "My unique id";
        String aesSeed = "My AES Secret Seed";

        System.out.println("====================================================");
        System.out.println("            CryptoLib PIN Block Demo");
        System.out.println("====================================================");
        System.out.println("PIN: " + pin);
        System.out.println("PAN: " + pan);
        System.out.println();

        // 3DES Key setup
        byte[] b3DesKey = TripleDes.buildKey(desSeed);
        System.out.println("3DES Key (Hex): " + Hex.encodeHexString(b3DesKey).toUpperCase());

        // AES Key setup (Format 4)
        byte[] bAesKey = AesCipher.buildKey(aesSeed, 128);
        System.out.println("AES Key  (Hex): " + Hex.encodeHexString(bAesKey).toUpperCase());
        System.out.println();

        // Format 0 Demo
        System.out.println("---------------- [Format 0: ISO-0 / ANSI X9.8] ----------------");
        String format0Block = Pinblock.encodeFormat0(pin, pan, b3DesKey);
        String format0Pin = Pinblock.decodeFormat0(format0Block, pan, b3DesKey);
        System.out.println("Encrypted PIN Block (16 hex): " + format0Block);
        System.out.println("Decoded PIN:                  " + format0Pin);
        System.out.println();

        // Format 1 Demo
        System.out.println("---------------- [Format 1: ISO-1 / ECI-4] --------------------");
        String format1Block = Pinblock.encodeFormat1(pin, b3DesKey);
        String format1Pin = Pinblock.decodeFormat1(format1Block, b3DesKey);
        System.out.println("Encrypted PIN Block (16 hex): " + format1Block);
        System.out.println("Decoded PIN:                  " + format1Pin);
        System.out.println();

        // Format 2 Demo
        System.out.println("---------------- [Format 2: ISO-2 / Smart Card] ---------------");
        String format2Clear = Pinblock.encodeFormat2Clear(pin);
        String format2Encrypted = Pinblock.encodeFormat2(pin, b3DesKey);
        String format2Pin = Pinblock.decodeFormat2(format2Encrypted, b3DesKey);
        System.out.println("Clear PIN Block (16 hex):     " + format2Clear);
        System.out.println("Encrypted PIN Block (16 hex): " + format2Encrypted);
        System.out.println("Decoded PIN:                  " + format2Pin);
        System.out.println();

        // Format 3 Demo
        System.out.println("---------------- [Format 3: ISO-3 / Random Fill] --------------");
        String format3Block = Pinblock.encodeFormat3(pin, pan, b3DesKey);
        String format3Pin = Pinblock.decodeFormat3(format3Block, pan, b3DesKey);
        System.out.println("Encrypted PIN Block (16 hex): " + format3Block);
        System.out.println("Decoded PIN:                  " + format3Pin);
        System.out.println();

        // Format 4 Demo
        System.out.println("---------------- [Format 4: ISO-4 / AES 128-bit] --------------");
        String format4Block = Pinblock.encodeFormat4(pin, pan, bAesKey);
        String format4Pin = Pinblock.decodeFormat4(format4Block, pan, bAesKey);
        System.out.println("Encrypted PIN Block (32 hex): " + format4Block);
        System.out.println("Decoded PIN:                  " + format4Pin);
        System.out.println();

        // Unified API Demo
        System.out.println("---------------- [Unified API Demo] ---------------------------");
        for (PinBlockFormat format : PinBlockFormat.values()) {
            byte[] key = (format == PinBlockFormat.ISO_4) ? bAesKey : b3DesKey;
            String block = Pinblock.encode(format, pin, pan, key);
            String recovered = Pinblock.decode(format, block, pan, key);
            System.out.println(String.format("%-6s -> Block: %s (Decoded: %s)", format.name(), block, recovered));
        }

        System.out.println("====================================================");
    }
}
