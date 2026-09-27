# CryptoLib in Java

A Java cryptographic library for electronic payment systems implementing **ISO 9564-1** PIN block formats and ciphers (3DES & AES).

## Supported PIN Block Formats (ISO 9564-1)

| Format | Cipher | Block Size | Uses PAN | Description |
| :--- | :--- | :--- | :--- | :--- |
| **ISO-0** | 3DES | 64-bit (16 hex) | Yes | ANSI X9.8 / VISA-1. PIN field XORed with 12 rightmost PAN digits, padded with `0xF`. |
| **ISO-1** | 3DES | 64-bit (16 hex) | No | ECI-4. Used when PAN is unavailable; filled with transaction sequence or random hex digits. |
| **ISO-2** | 3DES / Clear | 64-bit (16 hex) | No | Offline Smart Card / ICC verification format, padded with `0xF`. |
| **ISO-3** | 3DES | 64-bit (16 hex) | Yes | Similar to Format 0, but uses random fill digits (`0xA` to `0xF`) to resist dictionary attacks. |
| **ISO-4** | AES | 128-bit (32 hex) | Yes | ISO 9564-1:2015 AES format. Two-stage encipher-mix-encipher using full PAN and 8 random bytes. |

---

## Architecture & Format Details

### ISO-0 (Format 0)
- **PIN field:** `0` + `N` (length) + PIN digits + fill `F`s (16 nibbles)
- **PAN field:** `0000` + 12 rightmost digits of PAN (excluding check digit)
- **Block:** `3DES_Encrypt(PIN_field XOR PAN_field, Key)`

### ISO-1 (Format 1)
- **PIN field:** `1` + `N` (length) + PIN digits + transaction/random fill digits (16 nibbles)
- **Block:** `3DES_Encrypt(PIN_field, Key)`

### ISO-2 (Format 2)
- **PIN field:** `2` + `N` (length) + PIN digits + fill `F`s (16 nibbles)
- **Block:** Cleartext or `3DES_Encrypt(PIN_field, Key)`

### ISO-3 (Format 3)
- **PIN field:** `3` + `N` (length) + PIN digits + random fill digits in `[A-F]` (16 nibbles)
- **PAN field:** `0000` + 12 rightmost digits of PAN (excluding check digit)
- **Block:** `3DES_Encrypt(PIN_field XOR PAN_field, Key)`

### ISO-4 (Format 4 - AES 128-bit)
Defined in ISO 9564-1:2015 to support modern AES encryption:
- **PIN field (128-bit):** `4` + `N` (length) + PIN digits + `A` fill (to 16 nibbles) + 16 random hex nibbles (8 random bytes)
- **PAN field (128-bit):** `M` (where `M = PAN length - 12`) + full PAN + zero-padded to 32 nibbles
- **Encipherment Process:**
  1. `Intermediate A = AES_Encrypt(PIN_field, Key)`
  2. `Intermediate B = Intermediate A XOR PAN_field`
  3. `Final PIN Block = AES_Encrypt(Intermediate B, Key)`

---

## Code Examples

### Unified API
```java
import cryptolib.Pinblock;
import cryptolib.PinBlockFormat;

// Format 0 (3DES)
String block0 = Pinblock.encode(PinBlockFormat.ISO_0, "1234", pan, desKey);
String pin0   = Pinblock.decode(PinBlockFormat.ISO_0, block0, pan, desKey);

// Format 4 (AES 128-bit)
String block4 = Pinblock.encode(PinBlockFormat.ISO_4, "1234", pan, aesKey);
String pin4   = Pinblock.decode(PinBlockFormat.ISO_4, block4, pan, aesKey);
```

### Format-Specific Methods
```java
// Format 1 (No PAN required)
String block1 = Pinblock.encodeFormat1("1234", desKey);
String pin1   = Pinblock.decodeFormat1(block1, desKey);

// Format 2 (Smart Card / ICC)
String clearBlock = Pinblock.encodeFormat2Clear("1234"); // 241234FFFFFFFFFF
String block2     = Pinblock.encodeFormat2("1234", desKey);

// Format 3 (Random Fill)
String block3 = Pinblock.encodeFormat3("1234", pan, desKey);
String pin3   = Pinblock.decodeFormat3(block3, pan, desKey);

// Format 4 (AES)
String block4 = Pinblock.encodeFormat4("1234", pan, aesKey);
String pin4   = Pinblock.decodeFormat4(block4, pan, aesKey);
```

---

## Ciphers Included

- **`TripleDes.java`**: 3DES (DESede) in `ECB/NoPadding`, key derivation and 16-to-24 byte key makeup.
- **`AesCipher.java`**: AES in `ECB/NoPadding` (128-bit, 192-bit, 256-bit keys), key building and validation.

---

## Build & Test

### With Maven
```bash
mvn clean package
```

### Run Demo Application
```bash
cd cryptolib
java -cp target/cryptolib-0.1.0.jar cryptolib.PinBlockApp
```

### Run Benchmarks
```bash
cd benchmark
java -jar target/benchmarks.jar
```
