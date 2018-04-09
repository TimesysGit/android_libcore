/*
 * Copyright (C) 2018 Timesys Corporation
 * Copyright (C) 2018 GE Healthcare
 */

package org.fipscrypt;

import junit.framework.TestCase;

public class FIPSTest extends TestCase {

    public void test_FIPS_mode() throws Exception {
        int mode = NativeCrypto.FIPS_mode();

        assertTrue("FIPS mode set", mode != 0);
    }

}
