package org.cryptimeleon.predenc.kem.params;

import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanismTest;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanismTestParams;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05MasterSecret;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05PublicParameters;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05Setup;
import org.cryptimeleon.predenc.abe.fuzzy.large.Identity;
import org.cryptimeleon.predenc.paramgens.IBEFuzzySW05TestParamGenerator;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;
import org.cryptimeleon.predenc.kem.fuzzy.large.IBEFuzzySW05KEM;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Parameters used in {@link KeyEncapsulationMechanismTest} for the {@link IBEFuzzySW05KEM} and its symmetric variant.
 */
public class IBEFuzzySW05KEMParams {
    public static List<KeyEncapsulationMechanismTestParams> getParams() {
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, true);
        IBEFuzzySW05PublicParameters pp = setup.getPublicParameters();
        IBEFuzzySW05MasterSecret msk = setup.getMasterSecret();

        IBEFuzzySW05KEM fuzzy = new IBEFuzzySW05KEM(pp);
        SymmetricKeyPredicateKEM fuzzySymmetricKey = new SymmetricKeyPredicateKEM(fuzzy,
                new HashBasedKeyDerivationFunction());

        Identity omegaPubKey = IBEFuzzySW05TestParamGenerator.generatePublicKeyIdentity();
        Identity omegaValid = IBEFuzzySW05TestParamGenerator.generatePrivateKeyValidIdentity();
        Identity omegaCorrupted = IBEFuzzySW05TestParamGenerator.generatePrivateKeyCorruptedIdentity();

        // we can reuse the keys generated for kemScheme, since SymmetricKeyPredicateKEM is just a wrapper and uses the
        // same method internally
        EncryptionKey publicKey = fuzzy.generateEncryptionKey(omegaPubKey);
        DecryptionKey validSecretKey = fuzzy.generateDecryptionKey(msk, omegaValid);
        DecryptionKey corruptedSecretKey = fuzzy.generateDecryptionKey(msk, omegaCorrupted);

        KeyPair validKeyPair = new KeyPair(publicKey, validSecretKey);
        KeyPair corruptedKeyPair = new KeyPair(publicKey, corruptedSecretKey);

        List<KeyEncapsulationMechanismTestParams> toReturn = new ArrayList<>();
        toReturn.add(new KeyEncapsulationMechanismTestParams(fuzzy, validKeyPair, corruptedKeyPair));
        toReturn.add(new KeyEncapsulationMechanismTestParams(fuzzySymmetricKey, validKeyPair, corruptedKeyPair));

        return toReturn;
    }
}
