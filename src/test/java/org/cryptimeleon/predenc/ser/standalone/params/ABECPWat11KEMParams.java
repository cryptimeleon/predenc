package org.cryptimeleon.predenc.ser.standalone.params;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.kem.abe.cp.large.ABECPWat11KEM;

public class ABECPWat11KEMParams {

    public static StandaloneTestParams get() {
        ABECPWat11Setup setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
        return new StandaloneTestParams(ABECPWat11KEM.class,
                new ABECPWat11KEM(setup.getPublicParameters()));
    }

}
