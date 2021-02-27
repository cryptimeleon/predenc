package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05Setup;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05Small;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallKEM;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallSetup;
import org.cryptimeleon.predenc.kem.fuzzy.large.IBEFuzzySW05KEM;

import java.math.BigInteger;

public class FuzzyKEMStandaloneReprTests extends StandaloneReprSubTest {

    public void testFuzzyLargeKem() {
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);
        IBEFuzzySW05KEM kem = new IBEFuzzySW05KEM(setup.getPublicParameters());
        test(kem);
    }

    public void testFuzzySmallKem() {
        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();
        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 30; i++) {
            universe.add(new BigIntegerAttribute(i));
        }
        setup.doKeyGen(80, universe, BigInteger.valueOf(5), true);
        IBEFuzzySW05Small scheme = new IBEFuzzySW05Small(setup.getPublicParameters());
        IBEFuzzySW05SmallKEM kem = new IBEFuzzySW05SmallKEM(scheme);
        test(kem);
    }
}
