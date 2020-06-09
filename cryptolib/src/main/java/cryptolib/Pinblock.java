package cryptolib;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;


/**
 * Implementation of PinBlock Format 0 based on ISO-9564 standard
 * (https://en.wikipedia.org/wiki/ISO_9564)
 * 
 * The PIN block is constructed by [[XOR]]-ing two 64-bit fields: the ''plain
 * text PIN field'' and the ''account number field'', both of which comprise 16
 * four-bit [[nibble]]s.
 * 
 * The plain text PIN field is: one nibble with the value of 0, which identifies
 * this as a format 0 block one nibble encoding the length ''N'' of the PIN
 * ''N'' nibbles, each encoding one PIN digit 14−''N'' nibbles, each holding the
 * "[[Padding (cryptography)|fill]]" value 15 (i.e. 1111<sub>2</sub>)
 *
 * The account number field is: four nibbles with the value of zero 12 nibbles
 * containing the right-most 12 digits of the [[primary account number]] (PAN),
 * excluding the [[check digit]]
 * 
 * Extended PIN blocks and using 3DES as the encryption algorithm
 * 
 * For better clarification please refer to the following online tool:
 * https://neapay.com/online-tools/calculate-pin-block.html
 */

public class Pinblock {
	/**
	 * Encode pinblock format 0 (ISO 9564)
	 * 
	 * @param pin    pin
	 * @param pan    primary account number (PAN/CLN/CardNumber)
	 * @param key    the 3DES (EDE/ECB/NOPADDING) key
	 * @return pinblock in HEX format
	 */
	public static String encode(String pin, String pan, byte[] key) {
		try {
			final String pinLenHead = StringUtils.leftPad(Integer.toString(pin.length()), 2, '0') + pin;
			final String pinData = StringUtils.rightPad(pinLenHead, 16, 'F');
			final byte[] bPin = Hex.decodeHex(pinData.toCharArray());
			final String panPart = extractPanAccountNumberPart(pan);
			final String panData = StringUtils.leftPad(panPart, 16, '0');
			final byte[] bPan = Hex.decodeHex(panData.toCharArray());

			final byte[] pinblock = new byte[8];
			for (int i = 0; i < 8; i++)
				pinblock[i] = (byte) (bPin[i] ^ bPan[i]);

			final byte[] extendedPinblock = TripleDes.encrypt(pinblock, key, "DESede/ECB/NoPadding");

			return Hex.encodeHexString(extendedPinblock).toUpperCase();

		} catch (DecoderException e) {
			throw new RuntimeException("Hex decoder failed!", e);
		} 
	}

	/**
	 * @param accountNumber PAN - primary account number
	 * @return extract right-most 12 digits of the primary account number (PAN)
	 */
	private static String extractPanAccountNumberPart(String accountNumber) {
		String accountNumberPart = null;
		if (accountNumber.length() > 12)
			accountNumberPart = accountNumber.substring(accountNumber.length() - 13, accountNumber.length() - 1);
		else
			accountNumberPart = accountNumber;
		return accountNumberPart;
	}

	/**
	 * Decode pinblock format 0 - ISO 9564
	 * 
	 * @param pinblock pinblock in format 0 - ISO 9564 in HEX format
	 * @param pan      primary account number (PAN/CLN/CardNumber)
	 * @param key   the 3DES (EDE/ECB/NOPADDING) key 
	 * @return clean PIN
	 */
	public static String decode(String extendedPinBlock, String pan, byte[] key) {
		try {

			final byte[] bExtendedPinblock = Hex.decodeHex(extendedPinBlock.toCharArray());
			final byte[] bPinBlock = TripleDes.decrypt(bExtendedPinblock, key, "DESede/ECB/NoPadding");

			final String panPart = extractPanAccountNumberPart(pan);
			final String panData = StringUtils.leftPad(panPart, 16, '0');
			final byte[] bPan = Hex.decodeHex(panData.toCharArray());

			final byte[] bPin = new byte[8];
			for (int i = 0; i < 8; i++)
				bPin[i] = (byte) (bPinBlock[i] ^ bPan[i]);

			final String pinData = Hex.encodeHexString(bPin);
			final int pinLen = Integer.parseInt(pinData.substring(0, 2));
			return pinData.substring(2, 2 + pinLen);

		} catch (NumberFormatException e) {
			throw new RuntimeException("Invalid pinblock format!");
		} catch (DecoderException e) {
			throw new RuntimeException("Hex decoder failed!", e);
		} 
	}
}