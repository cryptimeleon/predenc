package org.cryptimeleon.predenc.enc.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.enc.TestParams;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05Small;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallMasterSecret;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallPublicParameters;
import org.cryptimeleon.predenc.abe.fuzzy.small.IBEFuzzySW05SmallSetup;

import java.math.BigInteger;
import java.util.function.Supplier;

public class IBEFuzzySW05SmallParams {

    public static TestParams getParams() {

        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();

        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 30; i++) {
            universe.add(new BigIntegerAttribute(i));
        }

        setup.doKeyGen(80, universe, BigInteger.valueOf(3), true);

        IBEFuzzySW05SmallPublicParameters pp = setup.getPublicParameters();

        IBEFuzzySW05SmallMasterSecret msk = setup.getMasterSecret();

        IBEFuzzySW05Small fuzzy = new IBEFuzzySW05Small(pp);

        SetOfAttributes omega0 = new SetOfAttributes();
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(20)));

        SetOfAttributes omega1 = new SetOfAttributes();
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(9)));


        SetOfAttributes omega2 = new SetOfAttributes();
        omega2.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega2.add(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega2.add(new BigIntegerAttribute(BigInteger.valueOf(9)));
        omega2.add(new BigIntegerAttribute(BigInteger.valueOf(10)));
        omega2.add(new BigIntegerAttribute(BigInteger.valueOf(11)));
        omega2.add(new BigIntegerAttribute(BigInteger.valueOf(12)));


        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omega0);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omega1);
        DecryptionKey corruptedSecretKey = fuzzy.generateDecryptionKey(msk, omega2);
        Supplier<PlainText> supplier =
                () -> ((PlainText) new GroupElementPlainText(pp.getGroupGT().getUniformlyRandomElement()));

        KeyPair validKeyPair = new KeyPair(publicKey, validSecretKey);
        KeyPair corruptedKeyPair = new KeyPair(publicKey, corruptedSecretKey);
        return new TestParams(fuzzy, supplier, validKeyPair, corruptedKeyPair);
    }
}