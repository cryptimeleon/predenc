package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;
import org.cryptimeleon.predenc.kem.abe.cp.large.ABECPWat11KEM;

public class ABECPWat11StandaloneReprTests extends StandaloneReprSubTest {

    ABECPWat11Setup setup;
    ABECPWat11KEM kem;

    public ABECPWat11StandaloneReprTests() {
        setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
        kem = new ABECPWat11KEM(setup.getPublicParameters());
    }

    public void testScheme() {
        test(new ABECPWat11(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        test(kem);
    }

    public void testSymmetricKem() {
        HashBasedKeyDerivationFunction kdf = new HashBasedKeyDerivationFunction();
        test(new SymmetricKeyPredicateKEM(kem, kdf));
    }
}
