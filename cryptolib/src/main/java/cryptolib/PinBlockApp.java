package cryptolib;

import org.apache.commons.codec.binary.Hex;

public class PinBlockApp 
{
    public static void main( String[] args )
    {
        String pin = "1234";
        String pan = "6037997390214444";
        String keySeed = "My uinque id";
        System.out.println( "PIN : " + pin);
        System.out.println( "PAN : " + pan);
        System.out.println( "Seed to generate key : " + keySeed);
        
        byte[] bKey = TripleDes.buildKey(keySeed);
        System.out.println( "3DES Key in Hex String : " + Hex.encodeHexString(bKey));
      
        
        String extendedPinBlock = Pinblock.encode(pin, pan, bKey);
        System.out.println("");
        System.out.println( "------------------ Encrption process ------------------" );
        System.out.println( "Extended Pin Block : " + extendedPinBlock);
      
        String decryptedPinBlock = Pinblock.decode(extendedPinBlock, pan, bKey);
        System.out.println("");
        System.out.println( "------------------ Decryption process ------------------" );
        System.out.println( "Decrypted Pin Block : " + decryptedPinBlock);
    }
}
