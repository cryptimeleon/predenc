package org.cryptimeleon.predenc.enc.representation.params;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.representation.RepresentationTest;
import org.cryptimeleon.craco.enc.representation.RepresentationTestParams;
import org.cryptimeleon.predenc.abe.fuzzy.large.*;
import org.cryptimeleon.predenc.enc.representation.PredEncRepresentationTestParams;
import org.cryptimeleon.predenc.paramgens.IBEFuzzySW05TestParamGenerator;

import java.math.BigInteger;

/**
 * Parameters used in the {@link RepresentationSubTest} for the Fuzzy IBE scheme {@link IBEFuzzySW05}.
 */
public class IBEFuzzySW05Params {

    public static RepresentationTestParams getParams() {
        // setup Fuzzy environment with security parameter = 80, number of attributes = 6, threshold = 3
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);

        IBEFuzzySW05PublicParameters pp = setup.getPublicParameters();
        IBEFuzzySW05MasterSecret msk = setup.getMasterSecret();
        IBEFuzzySW05 fuzzy = new IBEFuzzySW05(pp);

        // generate identities to test
        Identity omegaPubKey = IBEFuzzySW05TestParamGenerator.generatePublicKeyIdentity();
        Identity omegaValidPrivKey = IBEFuzzySW05TestParamGenerator.generatePrivateKeyValidIdentity();

        // generate key pair corresponding to the identities generated before
        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omegaPubKey);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omegaValidPrivKey);

        // encrypt random plaintext under the public key generated before
        PlainText plaintext = new GroupElementPlainText(pp.getGroupGT().getUniformlyRandomElement());
        CipherText ciphertext = fuzzy.encrypt(plaintext, publicKey);

        return new PredEncRepresentationTestParams(fuzzy, publicKey, validSecretKey, plaintext, ciphertext, msk);
    }
}
