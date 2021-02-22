package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06Small;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallKEM;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;

import java.util.ArrayList;
import java.util.Collection;

public class ABEKPGPSW06SmallParams {

    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();
        SetOfAttributes universe = new SetOfAttributes(
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        );
        setup.doKeyGen(80, universe, true);
        ABEKPGPSW06Small scheme = new ABEKPGPSW06Small(setup.getPublicParameters());
        ABEKPGPSW06SmallKEM kem = new ABEKPGPSW06SmallKEM(scheme);
        toReturn.add(new StandaloneTestParams(scheme.getClass(), scheme));
        toReturn.add(new StandaloneTestParams(kem.getClass(), kem));
        toReturn.add(new StandaloneTestParams(setup.getPublicParameters().getClass(), setup.getPublicParameters()));
        return toReturn;
    }
}
