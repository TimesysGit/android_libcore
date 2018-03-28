package org.conscrypt;

import java.lang.reflect.Method;
import junit.framework.TestCase;

public class RunAll {
	private static final String[] ALL_CLASSES = new String[] {
		"com.android.org.conscrypt.CertPinManagerTest",
		"com.android.org.conscrypt.ChainStrengthAnalyzerTest",
		"com.android.org.conscrypt.CipherSuiteTest",
		"com.android.org.conscrypt.ClientSessionContextTest",
		"com.android.org.conscrypt.FileClientSessionCacheTest",
		"com.android.org.conscrypt.MacTest",
		"com.android.org.conscrypt.NativeCryptoTest",
		"com.android.org.conscrypt.OpenSSLSignatureTest",
		"com.android.org.conscrypt.SignatureTest",
		"com.android.org.conscrypt.TrustedCertificateStoreTest",
		"com.android.org.conscrypt.TrustManagerImplTest",
	};

	public RunAll() {
		// do nothing
	}

	private static final boolean processTest(Class c, String funcName) {
		TestCase t;
		try {
			t = (TestCase)c.newInstance();
		} catch(Exception e) {
			System.err.println(c.getName() + " FAILED: " + e);
			return false;
		}

		t.setName(funcName);

		try {
			t.run();
		} catch(Exception e) {
			System.out.print(c.getName() + ":" + funcName +
				" FAILED!");
			return false;
		} finally {
			System.out.print(c.getName() + ":" + funcName +
				" Success");
		}

		return true;
	}

	private static final boolean processClass(String className) {
		Class c;
		Method[] functionList;

		try {
			c = Class.forName(className);
			functionList = c.getDeclaredMethods();
		} catch(Exception e) {
			System.err.println(e);
			return false;
		}

		boolean res = true;

		for (int i=0; i<functionList.length; i++) {
			final Method m = functionList[i];


			if (m.getReturnType() == void.class &&
			    m.getParameterTypes().length == 0) {
				final String name = m.getName();
				if (name.startsWith("test"))
					res&= processTest(c, name);
			}
		}

		return res;
	}

	private static final boolean processList(String classes[]) {
		boolean res = true;

		for (int i=0; i<classes.length; i++)
			res&= processClass(classes[i]);

		return res;
	}

	public static final void main(String args[]) {
		boolean result;

		System.out.println("!!!! Starting Crypto Tests !!!!");

		if (args.length == 0)
			result = RunAll.processList(RunAll.ALL_CLASSES);
		else
			result = RunAll.processList(args);

		if (result)
			System.out.println("!!!! All Tests Succeeded !!!!");
		else
			System.out.println("!!!! Ended In Failure !!!!");

		System.exit(result ? 0 : 1);
	}
}
