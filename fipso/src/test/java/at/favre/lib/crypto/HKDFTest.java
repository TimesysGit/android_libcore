package at.favre.lib.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import junit.framework.TestCase;

public class HKDFTest extends TestCase {
    private Random rng = new SecureRandom();
    private byte[] getNextRandomBytes(int len) {
        byte[] r = new byte[len];
        rng.nextBytes(r);
        return r;
    }

    public void test_quickStarTest() throws Exception {
        byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};

        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(null, lowEntropyInput);
        byte[] outputKeyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, 64);

        assertEquals(64, outputKeyingMaterial.length);
    }

    public void test_simpleUseCase() throws Exception {
        //if no dynamic salt is available, a static salt is better than null
        byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte)
                0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

        //example input
        String userInput = "this is a user input with bad entropy";

        HKDF hkdf = HKDF.fromHmacSha256();

        //extract the "raw" data to create output with concentrated entropy
        byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, userInput.getBytes(StandardCharsets.UTF_8));

        //create expanded bytes for e.g. AES secret key and IV
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 16);
        byte[] expandedIv = hkdf.expand(pseudoRandomKey, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

        //Example boilerplate encrypting a simple string with created key/iv
        SecretKey key = new SecretKeySpec(expandedAesKey, "AES"); //AES-128 key
        byte[] message = "my secret message".getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(expandedIv));
        byte[] encrypted = cipher.doFinal(message);

        assertNotNull(encrypted);
        assertTrue(encrypted.length > 0);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(expandedIv));
        byte[] decrypted = cipher.doFinal(encrypted);

        assertEquals(Arrays.toString(message), Arrays.toString(decrypted));
        assertFalse(Arrays.equals(encrypted, decrypted));
    }

    public void test_customHmac() throws Exception {
        //don't use md5, this is just an example
        HKDF hkdfMd5 = HKDF.from(new HkdfMacFactory.Default("HmacMD5", Security.getProvider("SunJCE")));

        byte[] lowEntropyInput = new byte[]{0x62, 0x58, (byte) 0x84, 0x2C};
        byte[] outputKeyingMaterial = hkdfMd5.extractAndExpand(null, lowEntropyInput, null, 32);

        assertEquals(32, outputKeyingMaterial.length);
    }

    public void test_checkLength() throws Exception {
        int[] counts = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] ikm;
        byte[] salt;

        for (int i : counts) {
            ikm = getNextRandomBytes(i);
            salt = getNextRandomBytes(i * 2);
            checkLength(HKDF.fromHmacSha256().extract(salt, ikm), 32);
            checkLength(HKDF.fromHmacSha256().extract(null, ikm), 32);
            checkLength(HKDF.fromHmacSha256().extract(new byte[0], ikm), 32);
            checkLength(HKDF.fromHmacSha512().extract(salt, ikm), 64);
            checkLength(HKDF.fromHmacSha512().extract(null, ikm), 64);
            checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).extract(salt, ikm), 20);
            checkLength(HKDF.from(new HkdfMacFactory.Default("HmacMD5")).extract(ikm, salt), 16);

            assertFalse(Arrays.equals(HKDF.fromHmacSha256().extract(salt, ikm), HKDF.fromHmacSha512().extract(salt, ikm)));
            assertFalse(Arrays.equals(HKDF.fromHmacSha256().extract(salt, ikm), HKDF.from(HkdfMacFactory.Default.hmacSha1()).extract(salt, ikm)));
        }
    }

    private void checkLength(byte[] prk, int refOutLength) {
        assertEquals(refOutLength, prk.length);
    }

    public void testExtractFailures() throws Exception {
        try {
            HKDF.fromHmacSha256().extract(getNextRandomBytes(10), null);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha512().extract(null, new byte[0]);
            fail();
        } catch (Exception ignored) {
        }
    }

    public void testExpand() throws Exception {
        int[] lengthsPrk = {1, 16, 20, 32, 64};
        int[] lengthsOut = {1, 4, 7, 8, 16, 20, 24, 36, 48, 64, 69, 72, 96, 128, 256, 512};
        byte[] prk;
        byte[] info;
        for (int lengthPrk : lengthsPrk) {
            for (int lengthOut : lengthsOut) {
                prk = getNextRandomBytes(lengthPrk);
                info = getNextRandomBytes(lengthPrk);
                checkLength(HKDF.fromHmacSha256().expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha256().expand(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha256().expand(prk, new byte[0], lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha512().expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.fromHmacSha512().expand(prk, null, lengthOut), lengthOut);
                checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).expand(prk, info, lengthOut), lengthOut);
                checkLength(HKDF.from(new HkdfMacFactory.Default("HmacMD5")).expand(prk, info, lengthOut), lengthOut);

                if (lengthOut > 4) {
                    assertFalse(Arrays.equals(HKDF.fromHmacSha256().expand(prk, info, lengthOut), HKDF.fromHmacSha512().expand(prk, info, lengthOut)));
                    assertFalse(Arrays.equals(HKDF.fromHmacSha256().expand(prk, info, lengthOut), HKDF.from(HkdfMacFactory.Default.hmacSha1()).expand(prk, info, lengthOut)));
                }
            }
        }
    }

    public void testExpandFailures() throws Exception {
        try {
            HKDF.fromHmacSha256().expand(null, getNextRandomBytes(10), 16);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha256().expand(getNextRandomBytes(16), getNextRandomBytes(8), 0);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha256().expand(new byte[0], getNextRandomBytes(8), 16);
            fail();
        } catch (Exception ignored) {
        }

        try {
            HKDF.fromHmacSha256().expand(getNextRandomBytes(16), getNextRandomBytes(8), 256 * 32);
            fail();
        } catch (Exception ignored) {
        }
    }

    public void test_extractAndExpand() throws Exception {
        checkLength(HKDF.from(HkdfMacFactory.Default.hmacSha1()).extractAndExpand(getNextRandomBytes(20), getNextRandomBytes(16), null, 80), 80);
        checkLength(HKDF.fromHmacSha256().extractAndExpand(getNextRandomBytes(32), getNextRandomBytes(16), null, 80), 80);
        checkLength(HKDF.fromHmacSha512().extractAndExpand(getNextRandomBytes(64), getNextRandomBytes(250), null, 80), 80);
    }

    public void testLongInputExpand() throws Exception {
        byte[] longInput = getNextRandomBytes(1024 * 1024); //1 MiB
        checkLength(HKDF.fromHmacSha256().extract(null, longInput), 32);
    }

    public void testLongOutputExtract() throws Exception {
        int outLengthSha512 = 255 * 64;
        checkLength(HKDF.fromHmacSha512().expand(HKDF.fromHmacSha512().extract(null, new byte[16]), null, outLengthSha512), outLengthSha512);

        int outLengthSha256 = 255 * 32;
        checkLength(HKDF.fromHmacSha256().expand(HKDF.fromHmacSha256().extract(null, new byte[16]), null, outLengthSha256), outLengthSha256);
    }

    public void test_multiThreadParallelTest() throws Exception {
        ExecutorService executorService = Executors.newFixedThreadPool(32);
        final HKDF hkdf = HKDF.fromHmacSha256();

        for (int i = 0; i < 512; i++) {
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(2);

                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] start thread");

                        Random r = new Random();

                        Thread.sleep(r.nextInt(5));

                        byte[] ikm = getNextRandomBytes(r.nextInt(12) + 12);
                        byte[] salt = getNextRandomBytes(r.nextInt(32));
                        byte[] prk = hkdf.extract(salt, ikm);

                        assertTrue(hkdf.getMacFactory().createInstance(new byte[1]).getMacLength() == prk.length);

                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] prk: " + Hex.encodeHexString(prk));

                        Thread.sleep(r.nextInt(5));

                        int length = 16 + r.nextInt(80);
                        byte[] okm = hkdf.expand(prk, null, length);
                        //System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] okm: " + Hex.encodeHexString(okm));
                        assertTrue(okm.length == length);

                        System.out.println("[" + System.nanoTime() + "|" + Thread.currentThread().getName() + "] end thread");
                    } catch (Exception e) {
                        fail(e.getMessage());
                    }
                }
            });
        }
        executorService.shutdown();
        executorService.awaitTermination(10, TimeUnit.SECONDS);
    }
}
