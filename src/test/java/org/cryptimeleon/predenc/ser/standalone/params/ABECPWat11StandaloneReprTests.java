package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;

public class ABECPWat11StandaloneReprTests extends StandaloneReprSubTest {

    ABECPWat11Setup setup;

    public ABECPWat11StandaloneReprTests() {
        setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
    }

    public void testScheme() {
        test(new ABECPWat11(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }
}
