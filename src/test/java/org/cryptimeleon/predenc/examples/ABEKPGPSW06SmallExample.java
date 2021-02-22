package org.cryptimeleon.predenc.examples;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.predenc.MasterSecret;
import org.cryptimeleon.predenc.abe.PredicateEncryptionScheme;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06Small;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallPublicParameters;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ABEKPGPSW06SmallExample {
    private PredicateEncryptionScheme predicateEncryptionScheme;

    private ABEKPGPSW06SmallPublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /* Creates a setup class that provides the algorithm parameters */
        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();

        /*
         * Creates the universe of attributes. THe KeyIndex/CipherTextIndex can
         * only use attributes out of this universe
         */
        SetOfAttributes universe = new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"),
                new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
        /*
         * Generates algorithm parameters: 80 = security level, universe
         * specifies the attributes that can be used in the key and cipher text
         */
        setup.doKeyGen(80, universe, false);

        /* The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /* Generates the encryption scheme */
        predicateEncryptionScheme = new ABEKPGPSW06Small(setup.getPublicParameters());
        /* The master secret is needed for the generation of a DecryptionKey */
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /* Generate a policy for the decryption key (KeyIndex) */
        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E"));
        /* Policy is ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE) */
        KeyIndex keyIndex = new ThresholdPolicy(2, leftNode, rightNode);
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);

        /* Generate a cipher text index for the encryption key */
        CiphertextIndex ciphertextIndex = new SetOfAttributes(new StringAttribute("A"), new StringAttribute("C"),
                new StringAttribute("D"));
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);
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
        ABEKPGPSW06SmallExample kp = new ABEKPGPSW06SmallExample();
        kp.setup();
        kp.generateKeys();
        kp.encryptDecrypt();
    }
}
