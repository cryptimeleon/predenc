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
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11PublicParameters;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ABECPWat11Example {

    private PredicateEncryptionScheme predicateEncryptionScheme;

    private ABECPWat11PublicParameters publicParameters;

    private MasterSecret masterSecret;

    private DecryptionKey decryptionKey;

    private EncryptionKey encryptionKey;

    public void setup() {
        /* Creates a setup class that provides the algorithm parameters*/
        ABECPWat11Setup setup = new ABECPWat11Setup();

        /*
         * Generates algorithm parameters:
         * 80 = security level, 5 = the maximum number of attributes in a key, 5 = maximum number of leaf-node
         * attributes in a policy
         */
        setup.doKeyGen(80, 5, 5, false, false);

        /* The algorithm parameters */
        publicParameters = setup.getPublicParameters();

        /* Generates the encryption scheme*/
        predicateEncryptionScheme = new ABECPWat11(setup.getPublicParameters());
        /* The master secret is needed for the generation of a DecryptioKey*/
        masterSecret = setup.getMasterSecret();
    }

    public void generateKeys() {
        /* Generate a policy for the encryption key (CipherTextIndex)*/
        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode =
                new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
        /* Policy is ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE)*/
        CiphertextIndex ciphertextIndex = new ThresholdPolicy(2, leftNode, rightNode);
        encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);

        /* Generate a KeyIndex for the decryption key*/
        KeyIndex keyIndex =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("C"), new StringAttribute("D"));
        decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);
    }

    public void encryptDecrypt() {
        /* Encrypt a random element*/
        GroupElement randomElement = publicParameters.getGroupGT().getUniformlyRandomElement();
        PlainText plainText = new GroupElementPlainText(randomElement);
        /* Encrypt it*/
        CipherText cipherText = predicateEncryptionScheme.encrypt(plainText, encryptionKey);
        /* Decrypt it again*/
        PlainText decryptedPlainText = predicateEncryptionScheme.decrypt(cipherText, decryptionKey);
        assertEquals(plainText, decryptedPlainText);
    }

    public static void main(String[] args) {
        ABECPWat11Example cp = new ABECPWat11Example();
        cp.setup();
        cp.generateKeys();
        cp.encryptDecrypt();
    }
}
