package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmall;
import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmallPublicParameters;
import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmallSetup;

import java.util.ArrayList;
import java.util.Collection;

public class ABECPWat11AsymSmallParams {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        ABECPWat11AsymSmallSetup setup = new ABECPWat11AsymSmallSetup();
        SetOfAttributes universe =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                        new StringAttribute("D"), new StringAttribute("E"));
        setup.doKeyGen(80, universe, true);
        toReturn.add(new StandaloneTestParams(ABECPWat11AsymSmallPublicParameters.class, setup.getPublicParameters()));
        ABECPWat11AsymSmall small = new ABECPWat11AsymSmall(setup.getPublicParameters());
        toReturn.add(new StandaloneTestParams(ABECPWat11AsymSmall.class, small));

        return toReturn;
    }
}
