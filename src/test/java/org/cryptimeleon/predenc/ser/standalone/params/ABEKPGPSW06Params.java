package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTest;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06PublicParameters;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06Setup;
import org.cryptimeleon.predenc.kem.abe.kp.large.ABEKPGPSW06KEM;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Parameters used in {@link StandaloneTest} for the KP-ABE large universe family.
 */
public class ABEKPGPSW06Params {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        // setup KP-ABE environment with security parameter = 60, number of attributes = 5
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 5, false, true);

        // add KP public org.cryptimeleon.groupsig.params to test
        ABEKPGPSW06PublicParameters kpp = setup.getPublicParameters();
        toReturn.add(new StandaloneTestParams(ABEKPGPSW06PublicParameters.class, kpp));

        // add KP-ABE large universe construction to test
        ABEKPGPSW06 scheme = new ABEKPGPSW06(kpp);
        toReturn.add(new StandaloneTestParams(ABEKPGPSW06.class, scheme));

        // add more efficient KP-ABE KEM large universe construction to test
        ABEKPGPSW06KEM kem = new ABEKPGPSW06KEM(kpp);
        toReturn.add(new StandaloneTestParams(kem));

        return toReturn;
    }
}
