package org.cryptimeleon.predenc.enc.params;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.enc.TestParams;
import org.cryptimeleon.predenc.abe.fuzzy.large.*;
import org.cryptimeleon.predenc.paramgens.IBEFuzzySW05TestParamGenerator;

import java.math.BigInteger;
import java.util.function.Supplier;

public class IBEFuzzySW05Params {

    public static TestParams getParams() {
        // setup Fuzzy environment with security parameter = 60, number of attributes = 6, threshold = 3
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);

        IBEFuzzySW05PublicParameters pp = setup.getPublicParameters();
        IBEFuzzySW05MasterSecret msk = setup.getMasterSecret();
        IBEFuzzySW05 fuzzy = new IBEFuzzySW05(pp);

        // generate identities for testing
        Identity omegaPubKey = IBEFuzzySW05TestParamGenerator.generatePublicKeyIdentity();
        Identity omegaValid = IBEFuzzySW05TestParamGenerator.generatePrivateKeyValidIdentity();
        Identity omegaCorrupted = IBEFuzzySW05TestParamGenerator.generatePrivateKeyCorruptedIdentity();

        // key generation based on the identities generated before
        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omegaPubKey);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omegaValid);
        DecryptionKey corruptedSecretKey = fuzzy.generateDecryptionKey(msk, omegaCorrupted);

        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                pp.getGroupGT().getUniformlyRandomElement()));

        KeyPair validKeyPair = new KeyPair(publicKey, validSecretKey);
        KeyPair corruptedKeyPair = new KeyPair(publicKey, corruptedSecretKey);

        return new TestParams(fuzzy, supplier, validKeyPair, corruptedKeyPair);
    }
}
