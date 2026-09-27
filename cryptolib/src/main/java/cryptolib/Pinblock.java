package cryptolib;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import java.security.SecureRandom;

/**
 * Implementation of ISO 9564-1 PIN Block formats:
 * <ul>
 *   <li><b>Format 0 (ISO-0):</b> ANSI X9.8 / VISA-1, 64-bit 3DES block, XORed with PAN, 'F' fill.</li>
 *   <li><b>Format 1 (ISO-1):</b> ECI-4, 64-bit 3DES block, no PAN, transaction/random fill.</li>
 *   <li><b>Format 2 (ISO-2):</b> ICC / Smart card offline format, 64-bit, 'F' fill.</li>
 *   <li><b>Format 3 (ISO-3):</b> 64-bit 3DES block, XORed with PAN, random fill (0xA-0xF).</li>
 *   <li><b>Format 4 (ISO-4):</b> ISO 9564-1:2015, 128-bit AES block, two-stage encipher-mix-encipher with PAN.</li>
 * </ul>
 */
public class Pinblock {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
    private static final char[] FORMAT3_FILL_CHARS = "ABCDEF".toCharArray();

    // =========================================================================
    // Unified API
    // =========================================================================

    /**
     * Encode a PIN block in the specified ISO 9564 format.
     *
     * @param format PIN block format (ISO_0, ISO_1, ISO_2, ISO_3, ISO_4)
     * @param pin    clean PIN (4 to 12 digits)
     * @param pan    primary account number (required for ISO_0, ISO_3, ISO_4; ignored for ISO_1, ISO_2)
     * @param key    cryptographic key (3DES key for formats 0-3; AES key for format 4)
     * @return enciphered PIN block in HEX string format
     */
    public static String encode(PinBlockFormat format, String pin, String pan, byte[] key) {
        if (format == null) {
            throw new IllegalArgumentException("PIN block format cannot be null");
        }
        switch (format) {
            case ISO_0:
                return encodeFormat0(pin, pan, key);
            case ISO_1:
                return encodeFormat1(pin, key);
            case ISO_2:
                return encodeFormat2(pin, key);
            case ISO_3:
                return encodeFormat3(pin, pan, key);
            case ISO_4:
                return encodeFormat4(pin, pan, key);
            default:
                throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    /**
     * Decode a PIN block of the specified ISO 9564 format.
     *
     * @param format   PIN block format (ISO_0, ISO_1, ISO_2, ISO_3, ISO_4)
     * @param pinBlock enciphered PIN block in HEX format
     * @param pan      primary account number (required for ISO_0, ISO_3, ISO_4; ignored for ISO_1, ISO_2)
     * @param key      cryptographic key (3DES key for formats 0-3; AES key for format 4)
     * @return clean PIN
     */
    public static String decode(PinBlockFormat format, String pinBlock, String pan, byte[] key) {
        if (format == null) {
            throw new IllegalArgumentException("PIN block format cannot be null");
        }
        switch (format) {
            case ISO_0:
                return decodeFormat0(pinBlock, pan, key);
            case ISO_1:
                return decodeFormat1(pinBlock, key);
            case ISO_2:
                return decodeFormat2(pinBlock, key);
            case ISO_3:
                return decodeFormat3(pinBlock, pan, key);
            case ISO_4:
                return decodeFormat4(pinBlock, pan, key);
            default:
                throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    // =========================================================================
    // Format 0 (ISO-0) - Backward compatible
    // =========================================================================

    /**
     * Encode pinblock format 0 (ISO 9564) - Backward compatible method.
     *
     * @param pin pin (4 to 12 digits)
     * @param pan primary account number (PAN/CardNumber)
     * @param key 3DES (EDE/ECB/NOPADDING) key
     * @return pinblock in HEX format
     */
    public static String encode(String pin, String pan, byte[] key) {
        return encodeFormat0(pin, pan, key);
    }

    /**
     * Decode pinblock format 0 - ISO 9564 - Backward compatible method.
     *
     * @param extendedPinBlock pinblock in format 0 in HEX format
     * @param pan              primary account number (PAN/CardNumber)
     * @param key              3DES (EDE/ECB/NOPADDING) key
     * @return clean PIN
     */
    public static String decode(String extendedPinBlock, String pan, byte[] key) {
        return decodeFormat0(extendedPinBlock, pan, key);
    }

    /**
     * Encode ISO 9564-1 Format 0 PIN block.
     *
     * @param pin clean PIN (4 to 12 digits)
     * @param pan primary account number
     * @param key 3DES key
     * @return 16-character HEX PIN block
     */
    public static String encodeFormat0(String pin, String pan, byte[] key) {
        validatePin(pin);
        validatePan(pan);
        try {
            final String pinLenHex = Integer.toHexString(pin.length()).toUpperCase();
            final String pinLenHead = "0" + pinLenHex + pin;
            final String pinData = StringUtils.rightPad(pinLenHead, 16, 'F');
            final byte[] bPin = Hex.decodeHex(pinData.toCharArray());

            final String panPart = extractPanAccountNumberPart(pan);
            final String panData = StringUtils.leftPad(panPart, 16, '0');
            final byte[] bPan = Hex.decodeHex(panData.toCharArray());

            final byte[] pinblock = new byte[8];
            for (int i = 0; i < 8; i++) {
                pinblock[i] = (byte) (bPin[i] ^ bPan[i]);
            }

            final byte[] extendedPinblock = TripleDes.encrypt(pinblock, key, "DESede/ECB/NoPadding");
            return Hex.encodeHexString(extendedPinblock).toUpperCase();
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Decode ISO 9564-1 Format 0 PIN block.
     *
     * @param extendedPinBlock 16-character HEX PIN block
     * @param pan              primary account number
     * @param key              3DES key
     * @return clean PIN
     */
    public static String decodeFormat0(String extendedPinBlock, String pan, byte[] key) {
        validatePan(pan);
        try {
            final byte[] bExtendedPinblock = Hex.decodeHex(extendedPinBlock.toCharArray());
            final byte[] bPinBlock = TripleDes.decrypt(bExtendedPinblock, key, "DESede/ECB/NoPadding");

            final String panPart = extractPanAccountNumberPart(pan);
            final String panData = StringUtils.leftPad(panPart, 16, '0');
            final byte[] bPan = Hex.decodeHex(panData.toCharArray());

            final byte[] bPin = new byte[8];
            for (int i = 0; i < 8; i++) {
                bPin[i] = (byte) (bPinBlock[i] ^ bPan[i]);
            }

            final String pinData = Hex.encodeHexString(bPin).toUpperCase();
            if (pinData.charAt(0) != '0') {
                throw new RuntimeException("Invalid PIN block format 0 control digit: " + pinData.charAt(0));
            }
            final int pinLen = Integer.parseInt(pinData.substring(1, 2), 16);
            validatePinLength(pinLen);
            return pinData.substring(2, 2 + pinLen);
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    // =========================================================================
    // Format 1 (ISO-1)
    // =========================================================================

    /**
     * Encode ISO 9564-1 Format 1 PIN block using random fill.
     *
     * @param pin clean PIN (4 to 12 digits)
     * @param key 3DES key
     * @return 16-character HEX PIN block
     */
    public static String encodeFormat1(String pin, byte[] key) {
        return encodeFormat1(pin, null, key);
    }

    /**
     * Encode ISO 9564-1 Format 1 PIN block with custom or deterministic fill.
     *
     * @param pin  clean PIN (4 to 12 digits)
     * @param fill custom fill hex characters (if null, random hex digits are generated)
     * @param key  3DES key
     * @return 16-character HEX PIN block
     */
    public static String encodeFormat1(String pin, String fill, byte[] key) {
        validatePin(pin);
        try {
            final String pinLenHex = Integer.toHexString(pin.length()).toUpperCase();
            final String prefix = "1" + pinLenHex + pin;
            final int neededFill = 16 - prefix.length();

            String fillData;
            if (fill != null) {
                if (fill.length() >= neededFill) {
                    fillData = fill.substring(0, neededFill).toUpperCase();
                } else {
                    fillData = StringUtils.rightPad(fill.toUpperCase(), neededFill, '0');
                }
            } else {
                fillData = randomHex(neededFill, HEX_CHARS);
            }

            final String pinData = prefix + fillData;
            final byte[] bPin = Hex.decodeHex(pinData.toCharArray());
            final byte[] extendedPinblock = TripleDes.encrypt(bPin, key, "DESede/ECB/NoPadding");
            return Hex.encodeHexString(extendedPinblock).toUpperCase();
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Decode ISO 9564-1 Format 1 PIN block.
     *
     * @param extendedPinBlock 16-character HEX PIN block
     * @param key              3DES key
     * @return clean PIN
     */
    public static String decodeFormat1(String extendedPinBlock, byte[] key) {
        try {
            final byte[] bExtendedPinblock = Hex.decodeHex(extendedPinBlock.toCharArray());
            final byte[] bPinBlock = TripleDes.decrypt(bExtendedPinblock, key, "DESede/ECB/NoPadding");
            final String pinData = Hex.encodeHexString(bPinBlock).toUpperCase();

            if (pinData.charAt(0) != '1') {
                throw new RuntimeException("Invalid PIN block format 1 control digit: " + pinData.charAt(0));
            }
            final int pinLen = Integer.parseInt(pinData.substring(1, 2), 16);
            validatePinLength(pinLen);
            return pinData.substring(2, 2 + pinLen);
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    // =========================================================================
    // Format 2 (ISO-2)
    // =========================================================================

    /**
     * Encode ISO 9564-1 Format 2 PIN block in clear text (unencrypted).
     * Format 2 is commonly used in ICC / smart card offline verification.
     *
     * @param pin clean PIN (4 to 12 digits)
     * @return 16-character clear HEX PIN block
     */
    public static String encodeFormat2Clear(String pin) {
        validatePin(pin);
        final String pinLenHex = Integer.toHexString(pin.length()).toUpperCase();
        final String pinLenHead = "2" + pinLenHex + pin;
        return StringUtils.rightPad(pinLenHead, 16, 'F');
    }

    /**
     * Decode ISO 9564-1 Format 2 clear PIN block.
     *
     * @param clearPinBlock 16-character clear HEX PIN block
     * @return clean PIN
     */
    public static String decodeFormat2Clear(String clearPinBlock) {
        if (clearPinBlock == null || clearPinBlock.length() != 16) {
            throw new IllegalArgumentException("Clear PIN block must be 16 hex characters");
        }
        final String pinData = clearPinBlock.toUpperCase();
        if (pinData.charAt(0) != '2') {
            throw new RuntimeException("Invalid PIN block format 2 control digit: " + pinData.charAt(0));
        }
        final int pinLen = Integer.parseInt(pinData.substring(1, 2), 16);
        validatePinLength(pinLen);
        return pinData.substring(2, 2 + pinLen);
    }

    /**
     * Encode ISO 9564-1 Format 2 PIN block with 3DES encryption.
     *
     * @param pin clean PIN (4 to 12 digits)
     * @param key 3DES key
     * @return 16-character HEX PIN block
     */
    public static String encodeFormat2(String pin, byte[] key) {
        try {
            final String clearBlock = encodeFormat2Clear(pin);
            final byte[] bPin = Hex.decodeHex(clearBlock.toCharArray());
            if (key == null) {
                return clearBlock;
            }
            final byte[] extendedPinblock = TripleDes.encrypt(bPin, key, "DESede/ECB/NoPadding");
            return Hex.encodeHexString(extendedPinblock).toUpperCase();
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Decode ISO 9564-1 Format 2 PIN block with 3DES decryption.
     *
     * @param pinBlock 16-character HEX PIN block
     * @param key      3DES key (or null if clear block)
     * @return clean PIN
     */
    public static String decodeFormat2(String pinBlock, byte[] key) {
        if (key == null) {
            return decodeFormat2Clear(pinBlock);
        }
        try {
            final byte[] bExtendedPinblock = Hex.decodeHex(pinBlock.toCharArray());
            final byte[] bPinBlock = TripleDes.decrypt(bExtendedPinblock, key, "DESede/ECB/NoPadding");
            return decodeFormat2Clear(Hex.encodeHexString(bPinBlock));
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    // =========================================================================
    // Format 3 (ISO-3)
    // =========================================================================

    /**
     * Encode ISO 9564-1 Format 3 PIN block using random fill (values 0xA to 0xF).
     *
     * @param pin clean PIN (4 to 12 digits)
     * @param pan primary account number
     * @param key 3DES key
     * @return 16-character HEX PIN block
     */
    public static String encodeFormat3(String pin, String pan, byte[] key) {
        return encodeFormat3(pin, pan, null, key);
    }

    /**
     * Encode ISO 9564-1 Format 3 PIN block with custom or deterministic fill.
     *
     * @param pin        clean PIN (4 to 12 digits)
     * @param pan        primary account number
     * @param randomFill custom fill hex string in range A-F (if null, generated randomly)
     * @param key        3DES key
     * @return 16-character HEX PIN block
     */
    public static String encodeFormat3(String pin, String pan, String randomFill, byte[] key) {
        validatePin(pin);
        validatePan(pan);
        try {
            final String pinLenHex = Integer.toHexString(pin.length()).toUpperCase();
            final String prefix = "3" + pinLenHex + pin;
            final int neededFill = 16 - prefix.length();

            String fillData;
            if (randomFill != null) {
                if (randomFill.length() >= neededFill) {
                    fillData = randomFill.substring(0, neededFill).toUpperCase();
                } else {
                    fillData = StringUtils.rightPad(randomFill.toUpperCase(), neededFill, 'F');
                }
            } else {
                fillData = randomHex(neededFill, FORMAT3_FILL_CHARS);
            }

            final String pinData = prefix + fillData;
            final byte[] bPin = Hex.decodeHex(pinData.toCharArray());

            final String panPart = extractPanAccountNumberPart(pan);
            final String panData = StringUtils.leftPad(panPart, 16, '0');
            final byte[] bPan = Hex.decodeHex(panData.toCharArray());

            final byte[] pinblock = new byte[8];
            for (int i = 0; i < 8; i++) {
                pinblock[i] = (byte) (bPin[i] ^ bPan[i]);
            }

            final byte[] extendedPinblock = TripleDes.encrypt(pinblock, key, "DESede/ECB/NoPadding");
            return Hex.encodeHexString(extendedPinblock).toUpperCase();
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Decode ISO 9564-1 Format 3 PIN block.
     *
     * @param extendedPinBlock 16-character HEX PIN block
     * @param pan              primary account number
     * @param key              3DES key
     * @return clean PIN
     */
    public static String decodeFormat3(String extendedPinBlock, String pan, byte[] key) {
        validatePan(pan);
        try {
            final byte[] bExtendedPinblock = Hex.decodeHex(extendedPinBlock.toCharArray());
            final byte[] bPinBlock = TripleDes.decrypt(bExtendedPinblock, key, "DESede/ECB/NoPadding");

            final String panPart = extractPanAccountNumberPart(pan);
            final String panData = StringUtils.leftPad(panPart, 16, '0');
            final byte[] bPan = Hex.decodeHex(panData.toCharArray());

            final byte[] bPin = new byte[8];
            for (int i = 0; i < 8; i++) {
                bPin[i] = (byte) (bPinBlock[i] ^ bPan[i]);
            }

            final String pinData = Hex.encodeHexString(bPin).toUpperCase();
            if (pinData.charAt(0) != '3') {
                throw new RuntimeException("Invalid PIN block format 3 control digit: " + pinData.charAt(0));
            }
            final int pinLen = Integer.parseInt(pinData.substring(1, 2), 16);
            validatePinLength(pinLen);
            return pinData.substring(2, 2 + pinLen);
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    // =========================================================================
    // Format 4 (ISO-4) - AES 128-bit
    // =========================================================================

    /**
     * Encode ISO 9564-1 Format 4 PIN block using random 8-byte salt and AES encryption.
     *
     * @param pin    clean PIN (4 to 12 digits)
     * @param pan    primary account number (12 to 19 digits)
     * @param aesKey AES key (16, 24, or 32 bytes)
     * @return 32-character HEX PIN block
     */
    public static String encodeFormat4(String pin, String pan, byte[] aesKey) {
        return encodeFormat4(pin, pan, null, aesKey);
    }

    /**
     * Encode ISO 9564-1 Format 4 PIN block with custom or deterministic 8-byte random salt.
     *
     * @param pin         clean PIN (4 to 12 digits)
     * @param pan         primary account number (12 to 19 digits)
     * @param randomBytes 8 random bytes for positions 17-32 (if null, generated using SecureRandom)
     * @param aesKey      AES key (16, 24, or 32 bytes)
     * @return 32-character HEX PIN block
     */
    public static String encodeFormat4(String pin, String pan, byte[] randomBytes, byte[] aesKey) {
        validatePin(pin);
        validatePan(pan);
        try {
            // 1. Construct 128-bit (32 nibbles) Plaintext PIN Field
            final String pinLenHex = Integer.toHexString(pin.length()).toUpperCase();
            final String pinPrefix = "4" + pinLenHex + pin;
            // Pad with 'A' to 16 nibbles (8 bytes)
            final String paddedPinPrefix = StringUtils.rightPad(pinPrefix, 16, 'A');

            // 16 random hex nibbles (8 bytes)
            byte[] saltBytes;
            if (randomBytes != null) {
                if (randomBytes.length != 8) {
                    throw new IllegalArgumentException("Format 4 random bytes must be exactly 8 bytes (16 hex nibbles)");
                }
                saltBytes = randomBytes;
            } else {
                saltBytes = new byte[8];
                RANDOM.nextBytes(saltBytes);
            }
            final String randomHexPart = Hex.encodeHexString(saltBytes).toUpperCase();
            final String pinFieldHex = paddedPinPrefix + randomHexPart;
            final byte[] bPinField = Hex.decodeHex(pinFieldHex.toCharArray());

            // 2. Construct 128-bit (32 nibbles) Plaintext PAN Field
            final byte[] bPanField = buildFormat4PanField(pan);

            // 3. Two-stage Encipher-Mix-Encipher:
            // Intermediate Block A = AES(PIN Field, Key)
            final byte[] intermediateA = AesCipher.encrypt(bPinField, aesKey);

            // Intermediate Block B = Intermediate Block A XOR PAN Field
            final byte[] intermediateB = new byte[16];
            for (int i = 0; i < 16; i++) {
                intermediateB[i] = (byte) (intermediateA[i] ^ bPanField[i]);
            }

            // Final Enciphered PIN Block = AES(Intermediate Block B, Key)
            final byte[] encipheredPinBlock = AesCipher.encrypt(intermediateB, aesKey);
            return Hex.encodeHexString(encipheredPinBlock).toUpperCase();
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Decode ISO 9564-1 Format 4 PIN block using AES decryption.
     *
     * @param extendedPinBlock 32-character HEX PIN block
     * @param pan              primary account number (12 to 19 digits)
     * @param aesKey           AES key (16, 24, or 32 bytes)
     * @return clean PIN
     */
    public static String decodeFormat4(String extendedPinBlock, String pan, byte[] aesKey) {
        validatePan(pan);
        if (extendedPinBlock == null || extendedPinBlock.length() != 32) {
            throw new IllegalArgumentException("Format 4 PIN block must be 32 hex characters (128 bits)");
        }
        try {
            final byte[] bExtendedPinBlock = Hex.decodeHex(extendedPinBlock.toCharArray());
            final byte[] bPanField = buildFormat4PanField(pan);

            // 1. Intermediate Block B = AES_Decrypt(Enciphered PIN Block, Key)
            final byte[] intermediateB = AesCipher.decrypt(bExtendedPinBlock, aesKey);

            // 2. Intermediate Block A = Intermediate Block B XOR PAN Field
            final byte[] intermediateA = new byte[16];
            for (int i = 0; i < 16; i++) {
                intermediateA[i] = (byte) (intermediateB[i] ^ bPanField[i]);
            }

            // 3. Plaintext PIN Field = AES_Decrypt(Intermediate Block A, Key)
            final byte[] bPinField = AesCipher.decrypt(intermediateA, aesKey);
            final String pinFieldHex = Hex.encodeHexString(bPinField).toUpperCase();

            // 4. Verify Control Field is '4'
            if (pinFieldHex.charAt(0) != '4') {
                throw new RuntimeException("Invalid PIN block format 4 control digit: " + pinFieldHex.charAt(0));
            }

            final int pinLen = Integer.parseInt(pinFieldHex.substring(1, 2), 16);
            validatePinLength(pinLen);
            return pinFieldHex.substring(2, 2 + pinLen);
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Build the 128-bit (16-byte / 32-nibble) PAN Field for ISO 9564-1 Format 4:
     * - First nibble M = PAN length - 12 (0 to 7). If PAN < 12 digits, M = 0 and PAN is left-padded to 12 with 0.
     * - Followed by the PAN digits.
     * - Remaining nibbles to the right are padded with '0' to complete 32 nibbles (16 bytes).
     *
     * @param pan primary account number
     * @return 16-byte PAN field
     */
    public static byte[] buildFormat4PanField(String pan) {
        final String cleanPan = pan.replaceAll("[\\s-]", "");
        int m;
        String formattedPan;
        if (cleanPan.length() >= 12) {
            m = cleanPan.length() - 12;
            if (m > 7) {
                throw new IllegalArgumentException("PAN length exceeds maximum 19 digits for Format 4: " + cleanPan.length());
            }
            formattedPan = cleanPan;
        } else {
            m = 0;
            formattedPan = StringUtils.leftPad(cleanPan, 12, '0');
        }

        final String mHex = Integer.toHexString(m).toUpperCase();
        final String panFieldData = StringUtils.rightPad(mHex + formattedPan, 32, '0');
        try {
            return Hex.decodeHex(panFieldData.toCharArray());
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed on PAN field: " + panFieldData, e);
        }
    }

    // =========================================================================
    // Helper & Validation Methods
    // =========================================================================

    /**
     * Extract right-most 12 digits of the primary account number (PAN), excluding the check digit.
     * Used in Format 0 and Format 3.
     *
     * @param accountNumber PAN - primary account number
     * @return right-most 12 digits excluding check digit
     */
    public static String extractPanAccountNumberPart(String accountNumber) {
        String cleanPan = accountNumber.replaceAll("[\\s-]", "");
        String accountNumberPart;
        if (cleanPan.length() > 12) {
            accountNumberPart = cleanPan.substring(cleanPan.length() - 13, cleanPan.length() - 1);
        } else {
            accountNumberPart = cleanPan;
        }
        return accountNumberPart;
    }

    private static void validatePin(String pin) {
        if (pin == null) {
            throw new IllegalArgumentException("PIN cannot be null");
        }
        if (pin.length() < 4 || pin.length() > 12) {
            throw new IllegalArgumentException("PIN length must be between 4 and 12 digits, got: " + pin.length());
        }
        for (int i = 0; i < pin.length(); i++) {
            if (!Character.isDigit(pin.charAt(i))) {
                throw new IllegalArgumentException("PIN must contain only numeric digits: " + pin);
            }
        }
    }

    private static void validatePan(String pan) {
        if (pan == null || pan.trim().isEmpty()) {
            throw new IllegalArgumentException("PAN cannot be null or empty");
        }
    }

    private static void validatePinLength(int pinLen) {
        if (pinLen < 4 || pinLen > 12) {
            throw new RuntimeException("Decoded PIN length out of valid range (4-12): " + pinLen);
        }
    }

    private static String randomHex(int length, char[] pool) {
        final StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(pool[RANDOM.nextInt(pool.length)]);
        }
        return sb.toString();
    }
}