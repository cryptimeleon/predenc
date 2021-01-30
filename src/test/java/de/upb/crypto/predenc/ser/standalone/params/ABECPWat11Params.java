package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.predenc.abe.cp.large.ABECPWat11;
import de.upb.crypto.predenc.abe.cp.large.ABECPWat11Setup;

import java.util.ArrayList;
import java.util.Collection;

public class ABECPWat11Params {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        ABECPWat11Setup setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
        toReturn.add(new StandaloneTestParams(ABECPWat11.class,
                new ABECPWat11(setup.getPublicParameters())));
        toReturn.add(new StandaloneTestParams(setup.getPublicParameters()));
        return toReturn;
    }
}
