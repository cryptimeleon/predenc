package de.upb.crypto.predenc.examples;

import de.upb.crypto.craco.common.attributes.BigIntegerAttribute;
import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.plaintexts.GroupElementPlainText;
import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.predenc.MasterSecret;
import de.upb.crypto.predenc.abe.PredicateEncryptionScheme;
import de.upb.crypto.predenc.abe.fuzzy.small.IBEFuzzySW05Small;
import de.upb.crypto.predenc.abe.fuzzy.small.IBEFuzzySW05SmallPublicParameters;
import de.upb.crypto.predenc.abe.fuzzy.small.IBEFuzzySW05SmallSetup;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class IBEFuzzySW05SmallExample {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private IBEFuzzySW05SmallPublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /* Creates a setup class that provides the algorithm parameters */
        IBEFuzzySW05SmallSetup setup = new IBEFuzzySW05SmallSetup();

        SetOfAttributes universe = new SetOfAttributes();
        for (int i = 1; i <= 10; i++) {
            universe.add(new BigIntegerAttribute(i));
        }

        /*
         * Generates algorithm parameters: 80 = security level, 10 = the
         * universe (meaning the the numbers 1 to 10 are in the universe), = 3
         * the required number of attributes in a the intersection
         */
        setup.doKeyGen(80, universe, BigInteger.valueOf(3), false);

        /* The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /* Generates the encryption scheme */
        predicateEncryptionScheme = new IBEFuzzySW05Small(setup.getPublicParameters());
        /* The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /* Create the Identity for the ciphertextIndex */
        SetOfAttributes omega0 = new SetOfAttributes();
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omega0.add(new BigIntegerAttribute(BigInteger.valueOf(6)));

        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(omega0);
        /* Create the Identity for the KeyIndex */
        SetOfAttributes omega1 = new SetOfAttributes();
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omega1.add(new BigIntegerAttribute(BigInteger.valueOf(9)));
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, omega1);

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
        IBEFuzzySW05SmallExample fuzzy = new IBEFuzzySW05SmallExample();
        fuzzy.setup();
        fuzzy.generateKeys();
        fuzzy.encryptDecrypt();
    }
}
