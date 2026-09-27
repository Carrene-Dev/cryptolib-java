package cryptolib;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * AES Cipher utility supporting 128-bit, 192-bit, and 256-bit encryption/decryption.
 * Commonly used with ECB/NoPadding for ISO 9564-1 Format 4 PIN blocks.
 */
public class AesCipher {

    public static final String DEFAULT_TRANSFORMATION = "AES/ECB/NoPadding";

    /**
     * Encrypt with AES using default transformation (AES/ECB/NoPadding)
     *
     * @param bMessage plain message in byte array (must be multiple of 16 bytes for NoPadding)
     * @param bKey     encryption key in byte array (16, 24, or 32 bytes)
     * @return cipher message
     */
    public static byte[] encrypt(byte[] bMessage, byte[] bKey) {
        return encrypt(bMessage, bKey, DEFAULT_TRANSFORMATION);
    }

    /**
     * Encrypt with AES
     *
     * @param bMessage       plain message in byte array
     * @param bKey           encryption key in byte array
     * @param transformation cipher transformation e.g. AES/ECB/NoPadding
     * @return cipher message
     */
    public static byte[] encrypt(byte[] bMessage, byte[] bKey, String transformation) {
        try {
            validateKey(bKey);
            final SecretKey secretKey = new SecretKeySpec(bKey, "AES");
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(bMessage);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("No Such Padding", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No Such Algorithm", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid Key", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("Bad Padding", e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("Illegal Block Size", e);
        }
    }

    /**
     * Decrypt with AES using default transformation (AES/ECB/NoPadding)
     *
     * @param bCipherMessage cipher message in byte array
     * @param bKey           encryption key in byte array (16, 24, or 32 bytes)
     * @return plain message
     */
    public static byte[] decrypt(byte[] bCipherMessage, byte[] bKey) {
        return decrypt(bCipherMessage, bKey, DEFAULT_TRANSFORMATION);
    }

    /**
     * Decrypt with AES
     *
     * @param bCipherMessage cipher message in byte array
     * @param bKey           encryption key in byte array
     * @param transformation cipher transformation e.g. AES/ECB/NoPadding
     * @return plain message
     */
    public static byte[] decrypt(byte[] bCipherMessage, byte[] bKey, String transformation) {
        try {
            validateKey(bKey);
            final SecretKey secretKey = new SecretKeySpec(bKey, "AES");
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(bCipherMessage);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("No Such Padding", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No Such Algorithm", e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Invalid Key", e);
        } catch (BadPaddingException e) {
            throw new RuntimeException("Bad Padding", e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("Illegal Block Size", e);
        }
    }

    /**
     * Decode a hex string representation of an AES key.
     * Validates that the key length is 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256).
     *
     * @param hexKey hex string representation of key (32, 48, or 64 hex characters)
     * @return byte array key
     */
    public static byte[] makeupKey(String hexKey) {
        if (hexKey == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        try {
            byte[] keyBytes = Hex.decodeHex(hexKey.toCharArray());
            validateKey(keyBytes);
            return keyBytes;
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    /**
     * Build an AES Key (default 128-bit) based on an initial seed string using SHA-256.
     *
     * @param keySeed initial seed string
     * @return 16-byte (128-bit) AES secret key
     */
    public static byte[] buildKey(String keySeed) {
        return buildKey(keySeed, 128);
    }

    /**
     * Build an AES Key based on an initial seed string using SHA-256.
     *
     * @param keySeed     initial seed string
     * @param keySizeBits 128, 192, or 256 bits
     * @return AES secret key in byte array
     */
    public static byte[] buildKey(String keySeed, int keySizeBits) {
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw new IllegalArgumentException("Key size must be 128, 192, or 256 bits");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(keySeed.getBytes("UTF-8"));
            return Arrays.copyOf(digest, keySizeBits / 8);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unsupported digest algorithm", e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unsupported encoding", e);
        }
    }

    private static void validateKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length: " + key.length + " bytes. Must be 16, 24, or 32 bytes.");
        }
    }
}
