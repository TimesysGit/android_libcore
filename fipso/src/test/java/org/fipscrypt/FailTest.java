/*
 * Copyright (C) 2018 Timesys Corporation
 * Copyright (C) 2018 GE Healthcare
 */

package org.fipscrypt;

import junit.framework.TestCase;

public class FailTest extends TestCase {

    public void test_Just_Fail() throws Exception {
        assertTrue("Always fail", false);
    }

}
