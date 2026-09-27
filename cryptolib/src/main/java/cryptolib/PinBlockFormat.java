package cryptolib;

/**
 * ISO 9564-1 PIN Block Formats
 */
public enum PinBlockFormat {
    /**
     * ISO 9564-1 Format 0 (ANSI X9.8 / VISA-1).
     * 64-bit block encrypted with 3DES.
     * PIN field is XORed with the PAN field (12 rightmost digits excluding check digit).
     * Padding is fixed with 0xF.
     */
    ISO_0('0', 8, true),

    /**
     * ISO 9564-1 Format 1 (ECI-4).
     * 64-bit block encrypted with 3DES.
     * Used when PAN is unavailable or not bound to PIN block.
     * Padding is transaction sequence number or random hex digits.
     */
    ISO_1('1', 8, false),

    /**
     * ISO 9564-1 Format 2.
     * 64-bit block used for offline smart card (ICC) verification.
     * Padding is fixed with 0xF. No PAN XOR.
     */
    ISO_2('2', 8, false),

    /**
     * ISO 9564-1 Format 3.
     * 64-bit block encrypted with 3DES.
     * Similar to Format 0, but uses random fill digits in range 0xA to 0xF.
     * PIN field is XORed with the PAN field.
     */
    ISO_3('3', 8, true),

    /**
     * ISO 9564-1 Format 4 (ISO 9564-1:2015).
     * 128-bit block encrypted with AES (AES-128/192/256).
     * Uses two-stage encipher-mix-encipher construction with full PAN and 8 random bytes.
     */
    ISO_4('4', 16, true);

    private final char formatCode;
    private final int blockSizeBytes;
    private final boolean panRequired;

    PinBlockFormat(char formatCode, int blockSizeBytes, boolean panRequired) {
        this.formatCode = formatCode;
        this.blockSizeBytes = blockSizeBytes;
        this.panRequired = panRequired;
    }

    public char getFormatCode() {
        return formatCode;
    }

    public int getBlockSizeBytes() {
        return blockSizeBytes;
    }

    public int getBlockSizeHex() {
        return blockSizeBytes * 2;
    }

    public boolean isPanRequired() {
        return panRequired;
    }

    /**
     * Identify format from format code character ('0', '1', '2', '3', '4').
     */
    public static PinBlockFormat fromCode(char code) {
        for (PinBlockFormat format : values()) {
            if (format.formatCode == code) {
                return format;
            }
        }
        throw new IllegalArgumentException("Unknown ISO 9564 PIN block format code: " + code);
    }
}
