package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06Setup;
import org.cryptimeleon.predenc.kem.abe.kp.large.ABEKPGPSW06KEM;

public class ABEKPGPSW06StandaloneReprTests extends StandaloneReprSubTest {

    ABEKPGPSW06Setup setup;

    public ABEKPGPSW06StandaloneReprTests() {
        setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 5, false, true);
    }

    public void testScheme() {
        test(new ABEKPGPSW06(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        test(new ABEKPGPSW06KEM(setup.getPublicParameters()));
    }
}
