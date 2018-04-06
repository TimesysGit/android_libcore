package at.favre.lib.crypto;

import javax.crypto.Mac;
import java.security.Security;
import junit.framework.TestCase;

public class HkdfMacFactoryTest extends TestCase {
    public void test_hmacSha256() throws Exception {
        testHmacFactory(HkdfMacFactory.Default.hmacSha256(), 32);
    }

    public void test_hmacSha512() throws Exception {
        testHmacFactory(HkdfMacFactory.Default.hmacSha512(), 64);
    }

    public void test_hmacSha1() throws Exception {
        testHmacFactory(HkdfMacFactory.Default.hmacSha1(), 20);
    }

    public void test_hmacMd5() throws Exception {
        testHmacFactory(new HkdfMacFactory.Default("HmacMD5"), 16);
    }

    public void test_customProvider() throws Exception {
        testHmacFactory(new HkdfMacFactory.Default("HmacSHA1", Security.getProvider("SunJCE")), 20);
    }

    public void test_hmacInstanceNotExisting() throws Exception {
        try {
            new HkdfMacFactory.Default("HmacNotExisting", null).createInstance(new byte[16]);
            fail();
        } catch(RuntimeException expected) { }
    }

    public void test_hmacUsingEmptyKey() throws Exception {
        try {
            HkdfMacFactory.Default.hmacSha256().createInstance(new byte[0]);
            fail();
        } catch(RuntimeException expected) { }
    }

    private void testHmacFactory(HkdfMacFactory macFactory, int refLength) {
        Mac mac = macFactory.createInstance(new byte[refLength]);
        assertNotNull(mac);

        mac.update(new byte[]{0x76, (byte) 0x92, 0x0E, 0x5E, (byte) 0x85, (byte) 0xDB, (byte) 0xA7, (byte) 0x8F});
        byte[] hash = mac.doFinal();
        assertEquals(refLength, hash.length);
    }
}
