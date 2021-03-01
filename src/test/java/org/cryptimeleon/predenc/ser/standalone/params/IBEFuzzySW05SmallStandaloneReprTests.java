package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05Small;
import org.cryptimeleon.predenc.kem.fuzzy.small.IBEFuzzySW05SmallKEM;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallSetup;

import java.math.BigInteger;

public class IBEFuzzySW05SmallStandaloneReprTests extends StandaloneReprSubTest {

    IBEFuzzySW05SmallSetup setup;

    public IBEFuzzySW05SmallStandaloneReprTests() {
        setup = new IBEFuzzySW05SmallSetup();
        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 30; i++) {
            universe.add(new BigIntegerAttribute(i));
        }
        setup.doKeyGen(80, universe, BigInteger.valueOf(5), true);
    }

    public void testScheme() {
        test(new IBEFuzzySW05Small(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        IBEFuzzySW05Small scheme = new IBEFuzzySW05Small(setup.getPublicParameters());
        IBEFuzzySW05SmallKEM kem = new IBEFuzzySW05SmallKEM(scheme);
        test(kem);
    }
}
