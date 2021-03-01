package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05Setup;
import org.cryptimeleon.predenc.kem.fuzzy.large.IBEFuzzySW05KEM;

import java.math.BigInteger;

public class IBEFuzzySW05StandaloneReprTests extends StandaloneReprSubTest {

    IBEFuzzySW05Setup setup;

    public IBEFuzzySW05StandaloneReprTests() {
        setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);
    }

    public void testScheme() {
        test(new IBEFuzzySW05(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        test(new IBEFuzzySW05KEM(setup.getPublicParameters()));
    }
}
