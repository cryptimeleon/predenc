package org.cryptimeleon.predenc.examples;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.predenc.MasterSecret;
import org.cryptimeleon.predenc.abe.PredicateEncryptionScheme;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05PublicParameters;
import org.cryptimeleon.predenc.abe.fuzzy.large.IBEFuzzySW05Setup;
import org.cryptimeleon.predenc.abe.fuzzy.large.Identity;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class IBEFuzzySW05Example {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private IBEFuzzySW05PublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /* Creates a setup class that provides the algorithm parameters */
        IBEFuzzySW05Setup setup = new IBEFuzzySW05Setup();

        /*
         * Generates algorithm parameters: 80 = security level, 6 = the maximum
         * number of attributes in a Identity, 3 the required number of
         * attributes in a the intersection
         */
        setup.doKeyGen(80, BigInteger.valueOf(6), BigInteger.valueOf(3), false, false);

        /* The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /* Generates the encryption scheme */
        predicateEncryptionScheme = new IBEFuzzySW05(setup.getPublicParameters());
        /* The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /* Create the Identity for the ciphertextIndex */
        Identity omega0 = new Identity();
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omega0.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));

        CiphertextIndex ciphertextIndex = (CiphertextIndex) omega0;
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);
        /* Create the Identity for the KeyIndex */
        Identity omega1 = new Identity();
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega1.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(9)));
        KeyIndex keyIndex = (KeyIndex) omega1;
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);

    }

    public void encryptDecrypt() {
        /* Encrypt a random element */
        GroupElement randomElement = publicParameters.getGroupGT().getUniformlyRandomElement();
        PlainText plainText = new GroupElementPlainText(randomElement);
        /* Encrypt it */
        CipherText cipherText = predicateEncryptionScheme.encrypt(plainText, encryptionKey);
        /* Decrypt it again */
        PlainText decryptedPlainText = predicateEncryptionScheme.decrypt(cipherText, decryptionKey);
        assertEquals(plainText, decryptedPlainText);
    }

    public static void main(String[] args) {
        IBEFuzzySW05Example fuzzy = new IBEFuzzySW05Example();
        fuzzy.setup();
        fuzzy.generateKeys();
        fuzzy.encryptDecrypt();
    }
}
