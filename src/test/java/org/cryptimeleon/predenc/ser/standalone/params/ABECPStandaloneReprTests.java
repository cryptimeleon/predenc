package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11Setup;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11Small;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11SmallSetup;
import org.cryptimeleon.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmall;
import org.cryptimeleon.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmallSetup;

public class ABECPStandaloneReprTests extends StandaloneReprSubTest {

    public void testCpLarge() {
        ABECPWat11Setup setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
        test(new ABECPWat11(setup.getPublicParameters()));
    }

    public void testCpSmall() {
        ABECPWat11SmallSetup setup = new ABECPWat11SmallSetup();
        SetOfAttributes universe =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                        new StringAttribute("D"), new StringAttribute("E"));
        setup.doKeyGen(80, universe, true);
        test(new ABECPWat11Small(setup.getPublicParameters()));
    }

    public void testCpSmallAsym() {
        ABECPWat11AsymSmallSetup setup = new ABECPWat11AsymSmallSetup();
        SetOfAttributes universe =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                        new StringAttribute("D"), new StringAttribute("E"));
        setup.doKeyGen(80, universe, true);
        test(new ABECPWat11AsymSmall(setup.getPublicParameters()));
    }

    public void testCpDistributed() {
        DistributedABECPWat11Setup setup = new DistributedABECPWat11Setup();
        setup.doKeyGen(80, 5, 4, 2, 2, true);
        test(new DistributedABECPWat11(setup.getPublicParameters()));
    }
}
