package cryptolib;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

public class TripleDesUnitTest {
    /**
     * Rigorous Test :-)
     * 
     * @throws UnsupportedEncodingException
     */
    @Test
    public void TestEncryption() throws UnsupportedEncodingException {
        String message = "12345678";
        byte[] bMessage = message.getBytes("utf-8");
        String key = "000102030405060708090A0B";
        byte[] bKey = key.getBytes("utf-8");
        byte[] bCipherMessage = TripleDes.encrypt(bMessage, bKey, "DESede/ECB/NoPadding");
        String cipherMessage = Base64.getEncoder().encodeToString(bCipherMessage);
        assertEquals(cipherMessage, "eFklvL5qUJQ=");
    }

    @Test
    public void TestDecryption() throws UnsupportedEncodingException, DecoderException
    {
        String cipherMessage = "eFklvL5qUJQ=";
        byte[] bCipherMessage = Base64.getDecoder().decode(cipherMessage);
        String key = "000102030405060708090A0B";
        byte[] bKey = key.getBytes("utf-8");
        byte[] bMessage = TripleDes.decrypt(bCipherMessage, bKey, "DESede/ECB/NoPadding");
        String message = new String(bMessage);
        assertEquals( message, "12345678");
    }
}