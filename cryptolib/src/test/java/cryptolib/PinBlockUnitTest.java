package cryptolib;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class PinBlockUnitTest 
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void TestEncoder()
    {
        String pin = "1234";
        String pan = "6037997390214444";
        String hexKey = "000102030405060708090A0B0C0D0E0F";
        byte[] bKey = TripleDes.makeupKey(hexKey);
        String extendedPinBlock = Pinblock.encode(pin, pan, bKey);
        assertEquals( extendedPinBlock, "C7933494F32B43F6");
    }

    @Test
    public void TestDecoder()
    {
        String pan = "6037997390214444";
        String hexKey = "000102030405060708090A0B0C0D0E0F";
        String extendedPinBlock = "C7933494F32B43F6";
        byte[] bKey = TripleDes.makeupKey(hexKey);
        String pin = Pinblock.decode(extendedPinBlock, pan, bKey);
        assertEquals( pin, "1234");
    }
}
