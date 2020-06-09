# CryptoLib in Java

## PinBlock in Java

Implementation of PinBlock Format 0 based on [ISO-9564](https://en.wikipedia.org/wiki/ISO_9564) standard.
The PIN block is constructed by `XOR`-ing two 64-bit fields: the `plain text PIN field` and the `account number field`,
both of which comprise 16 four-bit `nibble`s.

The plain text PIN field is :

- one nibble with the value of 0, which identifies this as a format 0 block
- one nibble encoding the length `N` of the PIN
- `N` nibbles, each encoding one PIN digit
- 14−`N` nibbles, each holding the `Padding (cryptography)|fill` value 15 (i.e. 1111 or F)

The account number field is:

- four nibbles with the value of zero
- 12 nibbles containing the right-most 12 digits of the primary account number(PAN), excluding the `check digit`

### Extended PIN blocks

Formats 0 to 3 are all suitable for use with the Triple Data Encryption Algorithm, as they correspond to its 64-bit block size. However the standard allows for other encryption algorithms with larger block sizes, e.g. the Advanced Encryption Standard has a block size of 128 bits. In such cases the PIN must be encoding into an extended PIN block, the format of which is defined in a 2015 amendment to ISO 9564-1.
In this library, we have used **3DES** in **ECB/NoPadding** mode.

For better clarification please refer to the following online tool:
https://neapay.com/online-tools/calculate-pin-block.html

## Triple DES in Java

- Build secret key based on an intial seed

- Makeup secret keys to be suitable for 3DES encryption

- Encryption / Decryption

## Debug/Run/Unit-test/Benchmark

This is provided to be built/test/run on [VS Code IDE](https://code.visualstudio.com/docs/java/java-tutorial) easily.
If you would like to build it in command line, you can use:

``` bash
mvn clean package
```

The unit-tests will be run automatically in this way.
But to run the sample `PinBlockApp.java` manually, you can run the following command:

```bash
cd cryptolib
java -cp target/cryptolib-0.1.0.jar cryptolib.PinBlockApp
```

Before running this command, please check the built `cryptolib` jar file version/name.

The benchmarks also can be run by the following commands:

```bash
cd benchmark
java -jar target/benchmarks.jar
```
