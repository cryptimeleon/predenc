package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05Small;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallKEM;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallSetup;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class IBEFuzzySW05SmallParams {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();
        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 30; i++) {
            universe.add(new BigIntegerAttribute(i));
        }
        setup.doKeyGen(80, universe, BigInteger.valueOf(5), true);
        IBEFuzzySW05Small scheme = new IBEFuzzySW05Small(setup.getPublicParameters());
        IBEFuzzySW05SmallKEM kem = new IBEFuzzySW05SmallKEM(scheme);
        toReturn.add(new StandaloneTestParams(scheme.getClass(), scheme));
        toReturn.add(new StandaloneTestParams(kem.getClass(), kem));
        toReturn.add(new StandaloneTestParams(setup.getPublicParameters().getClass(), setup.getPublicParameters()));
        return toReturn;
    }
}
