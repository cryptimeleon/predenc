package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06PublicParameters;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06Setup;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06Small;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallKEM;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;
import org.cryptimeleon.predenc.kem.abe.kp.large.ABEKPGPSW06KEM;

public class ABEKPKEMStandaloneReprTests extends StandaloneReprSubTest {

    public void testKpLargeKem() {
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 5, false, true);

        // add KP public org.cryptimeleon.groupsig.params to test
        ABEKPGPSW06PublicParameters kpp = setup.getPublicParameters();
        test(new ABEKPGPSW06KEM(kpp));
    }

    public void testKpSmallKem() {
        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();
        SetOfAttributes universe = new SetOfAttributes(
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        );
        setup.doKeyGen(80, universe, true);
        ABEKPGPSW06Small scheme = new ABEKPGPSW06Small(setup.getPublicParameters());
        test(new ABEKPGPSW06SmallKEM(scheme));
    }
}
