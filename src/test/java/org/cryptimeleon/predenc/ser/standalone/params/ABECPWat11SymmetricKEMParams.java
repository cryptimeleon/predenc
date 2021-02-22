package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;
import org.cryptimeleon.predenc.kem.abe.cp.large.ABECPWat11KEM;

public class ABECPWat11SymmetricKEMParams {
    public static StandaloneTestParams get() {
        final int securityParameter = 60;

        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number of attributes in the MSP)
        setup.doKeyGen(securityParameter, 5, 5, false, true);

        ABECPWat11KEM scheme = new ABECPWat11KEM(setup.getPublicParameters());
        HashBasedKeyDerivationFunction kdf = new HashBasedKeyDerivationFunction();
        SymmetricKeyPredicateKEM kemScheme = new SymmetricKeyPredicateKEM(scheme, kdf);

        return new StandaloneTestParams(SymmetricKeyPredicateKEM.class, kemScheme);
    }
}
