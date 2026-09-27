package cryptolib;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class PinBlockUnitTest {

    private static final String DEFAULT_PIN = "1234";
    private static final String DEFAULT_PAN = "6037997390214444";
    private static final String HEX_3DES_KEY = "000102030405060708090A0B0C0D0E0F";
    private static final String HEX_AES_KEY = "000102030405060708090A0B0C0D0E0F"; // 16 bytes = 128-bit

    // =========================================================================
    // Format 0 Tests
    // =========================================================================

    @Test
    public void testFormat0Encoder() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String extendedPinBlock = Pinblock.encode(DEFAULT_PIN, DEFAULT_PAN, bKey);
        assertEquals("C7933494F32B43F6", extendedPinBlock);
    }

    @Test
    public void testFormat0Decoder() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String extendedPinBlock = "C7933494F32B43F6";
        String pin = Pinblock.decode(extendedPinBlock, DEFAULT_PAN, bKey);
        assertEquals(DEFAULT_PIN, pin);
    }

    @Test
    public void testFormat0VariousPinLengths() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String[] testPins = new String[]{"1234", "123456", "12345678", "123456789012"};
        for (String pin : testPins) {
            String block = Pinblock.encodeFormat0(pin, DEFAULT_PAN, bKey);
            String recovered = Pinblock.decodeFormat0(block, DEFAULT_PAN, bKey);
            assertEquals(pin, recovered);
        }
    }

    // =========================================================================
    // Format 1 Tests
    // =========================================================================

    @Test
    public void testFormat1Roundtrip() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String block = Pinblock.encodeFormat1("5678", bKey);
        assertEquals(16, block.length());
        String recovered = Pinblock.decodeFormat1(block, bKey);
        assertEquals("5678", recovered);
    }

    @Test
    public void testFormat1DeterministicFill() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String fill = "0123456789";
        String block = Pinblock.encodeFormat1("1234", fill, bKey);
        String recovered = Pinblock.decodeFormat1(block, bKey);
        assertEquals("1234", recovered);
    }

    // =========================================================================
    // Format 2 Tests
    // =========================================================================

    @Test
    public void testFormat2Clear() {
        String clearBlock = Pinblock.encodeFormat2Clear("1234");
        assertEquals("241234FFFFFFFFFF", clearBlock);
        String recovered = Pinblock.decodeFormat2Clear(clearBlock);
        assertEquals("1234", recovered);
    }

    @Test
    public void testFormat2EncryptedRoundtrip() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String block = Pinblock.encodeFormat2("4321", bKey);
        assertEquals(16, block.length());
        String recovered = Pinblock.decodeFormat2(block, bKey);
        assertEquals("4321", recovered);
    }

    // =========================================================================
    // Format 3 Tests
    // =========================================================================

    @Test
    public void testFormat3Roundtrip() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String block = Pinblock.encodeFormat3("7890", DEFAULT_PAN, bKey);
        assertEquals(16, block.length());
        String recovered = Pinblock.decodeFormat3(block, DEFAULT_PAN, bKey);
        assertEquals("7890", recovered);
    }

    @Test
    public void testFormat3Randomization() {
        byte[] bKey = TripleDes.makeupKey(HEX_3DES_KEY);
        String block1 = Pinblock.encodeFormat3("7890", DEFAULT_PAN, bKey);
        String block2 = Pinblock.encodeFormat3("7890", DEFAULT_PAN, bKey);
        // Due to random fill digits, two blocks for the same PIN/PAN should differ
        assertNotEquals(block1, block2);
        assertEquals("7890", Pinblock.decodeFormat3(block1, DEFAULT_PAN, bKey));
        assertEquals("7890", Pinblock.decodeFormat3(block2, DEFAULT_PAN, bKey));
    }

    // =========================================================================
    // Format 4 Tests (AES 128-bit)
    // =========================================================================

    @Test
    public void testFormat4RoundtripAes128() {
        byte[] aesKey = AesCipher.makeupKey(HEX_AES_KEY);
        String block = Pinblock.encodeFormat4("9876", DEFAULT_PAN, aesKey);
        assertEquals(32, block.length()); // 128-bit block = 32 hex chars
        String recovered = Pinblock.decodeFormat4(block, DEFAULT_PAN, aesKey);
        assertEquals("9876", recovered);
    }

    @Test
    public void testFormat4RandomSaltDiffers() {
        byte[] aesKey = AesCipher.makeupKey(HEX_AES_KEY);
        String block1 = Pinblock.encodeFormat4("9876", DEFAULT_PAN, aesKey);
        String block2 = Pinblock.encodeFormat4("9876", DEFAULT_PAN, aesKey);
        // Random 8-byte salt produces different ciphertexts
        assertNotEquals(block1, block2);
        assertEquals("9876", Pinblock.decodeFormat4(block1, DEFAULT_PAN, aesKey));
        assertEquals("9876", Pinblock.decodeFormat4(block2, DEFAULT_PAN, aesKey));
    }

    @Test
    public void testFormat4DeterministicSalt() {
        byte[] aesKey = AesCipher.makeupKey(HEX_AES_KEY);
        byte[] salt = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        String block1 = Pinblock.encodeFormat4("1234", DEFAULT_PAN, salt, aesKey);
        String block2 = Pinblock.encodeFormat4("1234", DEFAULT_PAN, salt, aesKey);
        assertEquals(block1, block2);
        assertEquals("1234", Pinblock.decodeFormat4(block1, DEFAULT_PAN, aesKey));
    }

    @Test
    public void testFormat4PanLengths() {
        byte[] aesKey = AesCipher.makeupKey(HEX_AES_KEY);
        // Test 12-digit, 16-digit, 19-digit, and short PAN
        String[] pans = new String[]{
                "123456789012",                 // 12 digits
                "6037997390214444",             // 16 digits
                "1234567890123456789",         // 19 digits
                "1234567890"                    // 10 digits (< 12)
        };
        for (String pan : pans) {
            String block = Pinblock.encodeFormat4("1122", pan, aesKey);
            String recovered = Pinblock.decodeFormat4(block, pan, aesKey);
            assertEquals("PAN test failed for: " + pan, "1122", recovered);
        }
    }

    @Test
    public void testFormat4KeySizes() {
        // AES-128 (16 bytes), AES-192 (24 bytes), AES-256 (32 bytes)
        byte[] key128 = AesCipher.buildKey("seed-128", 128);
        byte[] key192 = AesCipher.buildKey("seed-192", 192);
        byte[] key256 = AesCipher.buildKey("seed-256", 256);

        byte[][] keys = new byte[][]{key128, key192, key256};
        for (byte[] key : keys) {
            String block = Pinblock.encodeFormat4("5566", DEFAULT_PAN, key);
            assertEquals(32, block.length());
            String recovered = Pinblock.decodeFormat4(block, DEFAULT_PAN, key);
            assertEquals("5566", recovered);
        }
    }

    // =========================================================================
    // Unified API Tests
    // =========================================================================

    @Test
    public void testUnifiedApiAllFormats() {
        byte[] desKey = TripleDes.makeupKey(HEX_3DES_KEY);
        byte[] aesKey = AesCipher.makeupKey(HEX_AES_KEY);

        for (PinBlockFormat format : PinBlockFormat.values()) {
            byte[] key = (format == PinBlockFormat.ISO_4) ? aesKey : desKey;
            String block = Pinblock.encode(format, "8765", DEFAULT_PAN, key);
            assertEquals(format.getBlockSizeHex(), block.length());

            String recovered = Pinblock.decode(format, block, DEFAULT_PAN, key);
            assertEquals("Failed for format " + format, "8765", recovered);
        }
    }

    // =========================================================================
    // Validation & Error Handling Tests
    // =========================================================================

    @Test(expected = IllegalArgumentException.class)
    public void testPinTooShort() {
        byte[] desKey = TripleDes.makeupKey(HEX_3DES_KEY);
        Pinblock.encodeFormat0("123", DEFAULT_PAN, desKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPinTooLong() {
        byte[] desKey = TripleDes.makeupKey(HEX_3DES_KEY);
        Pinblock.encodeFormat0("1234567890123", DEFAULT_PAN, desKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPinNonNumeric() {
        byte[] desKey = TripleDes.makeupKey(HEX_3DES_KEY);
        Pinblock.encodeFormat0("123A", DEFAULT_PAN, desKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullPan() {
        byte[] desKey = TripleDes.makeupKey(HEX_3DES_KEY);
        Pinblock.encodeFormat0("1234", null, desKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAesInvalidKeySize() {
        byte[] badKey = new byte[10]; // Not 16, 24, or 32
        AesCipher.encrypt(new byte[16], badKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFormat4InvalidBlockLength() {
        byte[] aesKey = AesCipher.makeupKey(HEX_AES_KEY);
        Pinblock.decodeFormat4("C7933494F32B43F6", DEFAULT_PAN, aesKey); // Only 16 chars instead of 32
    }
}
