package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11Small;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11SmallSetup;
import org.cryptimeleon.predenc.kem.abe.cp.small.ABECPWat11SmallKEM;

public class ABECPWat11SmallStandaloneReprTests extends StandaloneReprSubTest {

    ABECPWat11SmallSetup setup;
    ABECPWat11Small scheme;

    public ABECPWat11SmallStandaloneReprTests() {
        setup = new ABECPWat11SmallSetup();
        SetOfAttributes universe =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                        new StringAttribute("D"), new StringAttribute("E"));
        setup.doKeyGen(80, universe, true);
        scheme = new ABECPWat11Small(setup.getPublicParameters());
    }

    public void testScheme() {
        test(scheme);
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        test(new ABECPWat11SmallKEM(scheme));
    }
}
