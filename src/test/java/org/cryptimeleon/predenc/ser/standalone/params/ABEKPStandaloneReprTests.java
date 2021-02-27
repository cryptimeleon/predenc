package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06;
import org.cryptimeleon.predenc.abe.kp.large.ABEKPGPSW06Setup;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06Small;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;

public class ABEKPStandaloneReprTests extends StandaloneReprSubTest {

    public void testKpSmall() {
        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();
        SetOfAttributes universe = new SetOfAttributes(
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        );
        setup.doKeyGen(80, universe, true);
        test(new ABEKPGPSW06Small(setup.getPublicParameters()));
    }

    public void testKpLarge() {
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 5, false, true);
        test(new ABEKPGPSW06(setup.getPublicParameters()));
    }
}
