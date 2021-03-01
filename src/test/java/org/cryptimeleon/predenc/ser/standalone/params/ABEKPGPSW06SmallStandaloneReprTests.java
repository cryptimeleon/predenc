package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06Small;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallKEM;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;

public class ABEKPGPSW06SmallStandaloneReprTests extends StandaloneReprSubTest {

    ABEKPGPSW06SmallSetup setup;

    public ABEKPGPSW06SmallStandaloneReprTests() {
        setup = new ABEKPGPSW06SmallSetup();
        SetOfAttributes universe = new SetOfAttributes(
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        );
        setup.doKeyGen(80, universe, true);
    }

    public void testScheme() {
        test(new ABEKPGPSW06Small(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        test(new ABEKPGPSW06SmallKEM(new ABEKPGPSW06Small(setup.getPublicParameters())));
    }
}
