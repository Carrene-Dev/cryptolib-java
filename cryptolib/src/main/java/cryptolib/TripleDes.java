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

public class TripleDes {

    /**
	 * Encrypt in 3DES
	 * 
	 * @param bMessage          plain message in byte array
	 * @param bKey              encryption key in byte array
	 * @param transfoormation   the 3DES transformation e.g. DESede/ECB/NOPADDING
	 * @return cipher message
	 */
    public static byte[] encrypt(byte[] bMessage, byte[] bKey, String transformation)
    {
        try {
            final SecretKey secretKey = new SecretKeySpec(bKey, "DESede");
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            final byte[] bCipherMessage = cipher.doFinal(bMessage);
            return bCipherMessage;
        } catch (NoSuchPaddingException e) {
			throw new RuntimeException("No Such Padding", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No Such Algorithm", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid Key", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Invalid Key", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Invalid Key", e);
		}
    }

    /**
	 * Decrypt in 3DES
	 * 
	 * @param bCipherMessage    cipher message in byte array
	 * @param bKey              encryption key in byte array
	 * @param transfoormation   the 3DES transformation e.g. DESede/ECB/NOPADDING
	 * @return plain message
	 */
    public static byte[] decrypt(byte[] bCipherMessage, byte[] bKey, String transformation)
    {
        try {
            final SecretKey secretKey = new SecretKeySpec(bKey, "DESede");
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            final byte[] bMessage = cipher.doFinal(bCipherMessage);
            return bMessage;
        } catch (NoSuchPaddingException e) {
			throw new RuntimeException("No Such Padding", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("No Such Algorithm", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid Key", e);
		} catch (BadPaddingException e) {
			throw new RuntimeException("Invalid Key", e);
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Invalid Key", e);
		}
    }

    /**
	 * @param hexKey the 3DES (EDE/ECB/NOPADDING) key in hex string format
	 * @return make up a 24-bytes key by using the same 8-byte encription key if the
	 *         input key length is 16 bytes.
	 */
	public static byte[] makeupKey(String hexKey) {
		byte[] keyBytes;
		try {
			keyBytes = Hex.decodeHex(hexKey.toCharArray());
			final byte[] encryptionKey = Arrays.copyOf(keyBytes, 24);
			if (keyBytes.length == 16) {
				for (int j = 0, k = 16; j < 8;) {
					encryptionKey[k++] = keyBytes[j++];
				}
			}
			return encryptionKey;
		} catch (DecoderException e) {
			throw new RuntimeException("Hex decoder failed!", e);
		}
	}

    /**
	 * Build Key for 3DES based on an initial seed 
     *  
	 * @param keySeed   initial seed to build a key
	 * @return          3DES secret key
	 */
	public static byte[] buildKey(String keySeed) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			final byte[] digestOfPassword = md.digest(keySeed.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			return keyBytes;

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unsupported digest algorithm", e);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Unsupported encoding", e);
		}
	}
}