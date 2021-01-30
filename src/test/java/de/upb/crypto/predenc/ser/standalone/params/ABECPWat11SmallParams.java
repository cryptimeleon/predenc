package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11Small;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11SmallKEM;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11SmallPublicParameters;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11SmallSetup;

import java.util.ArrayList;
import java.util.Collection;

public class ABECPWat11SmallParams {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        ABECPWat11SmallSetup setup = new ABECPWat11SmallSetup();
        SetOfAttributes universe =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                        new StringAttribute("D"), new StringAttribute("E"));
        setup.doKeyGen(80, universe, true);
        toReturn.add(new StandaloneTestParams(ABECPWat11SmallPublicParameters.class, setup.getPublicParameters()));
        ABECPWat11Small small = new ABECPWat11Small(setup.getPublicParameters());
        ABECPWat11SmallKEM kem = new ABECPWat11SmallKEM(small);
        toReturn.add(new StandaloneTestParams(ABECPWat11Small.class, small));
        toReturn.add(new StandaloneTestParams(ABECPWat11SmallKEM.class, kem));

        return toReturn;
    }
}
