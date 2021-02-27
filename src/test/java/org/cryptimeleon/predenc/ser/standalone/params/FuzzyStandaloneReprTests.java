package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05Setup;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05Small;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallSetup;

import java.math.BigInteger;

public class FuzzyStandaloneReprTests extends StandaloneReprSubTest {
    public void testFuzzyLarge() {
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);
        test(new IBEFuzzySW05(setup.getPublicParameters()));
    }

    public void testFuzzySmall() {
        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();
        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 30; i++) {
            universe.add(new BigIntegerAttribute(i));
        }
        setup.doKeyGen(80, universe, BigInteger.valueOf(5), true);
        test(new IBEFuzzySW05Small(setup.getPublicParameters()));
    }
}
