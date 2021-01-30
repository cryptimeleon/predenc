package de.upb.crypto.predenc.enc.params;

import de.upb.crypto.craco.common.attributes.Attribute;
import de.upb.crypto.craco.common.attributes.BigIntegerAttribute;
import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.common.plaintexts.GroupElementPlainText;
import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.common.policies.ThresholdPolicy;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.enc.TestParams;
import de.upb.crypto.predenc.abe.kp.small.ABEKPGPSW06Small;
import de.upb.crypto.predenc.abe.kp.small.ABEKPGPSW06SmallMasterSecret;
import de.upb.crypto.predenc.abe.kp.small.ABEKPGPSW06SmallPublicParameters;
import de.upb.crypto.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Supplier;

public class ABEKPGPSW06SmallParams {

    public static ArrayList<TestParams> getParams() {
        Attribute[] stringAttributes = {
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        };
        TestParams stringAttrParams = createGenericParams(stringAttributes);
        Attribute[] integerAttribute = {
                new BigIntegerAttribute(0), new BigIntegerAttribute(1),
                new BigIntegerAttribute(2), new BigIntegerAttribute(3),
                new BigIntegerAttribute(4)
        };
        TestParams integerAttrParams = createGenericParams(integerAttribute);

        ArrayList<TestParams> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }

    private static TestParams createGenericParams(Attribute[] attributes) {

        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();
        setup.doKeyGen(80, Arrays.asList(attributes), true);

        ABEKPGPSW06SmallMasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06SmallPublicParameters publicParams = setup.getPublicParameters();

        ABEKPGPSW06Small scheme = new ABEKPGPSW06Small(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
        Policy validPolicy = new ThresholdPolicy(2, leftNode, rightNode);

        ThresholdPolicy invalidLeftNode = new ThresholdPolicy(2, attributes[0], attributes[1]);
        ThresholdPolicy invalidRightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
        Policy invalidPolicy = new ThresholdPolicy(2, invalidLeftNode, invalidRightNode);

        DecryptionKey validSK = scheme.generateDecryptionKey(msk, validPolicy);
        DecryptionKey invalidSK = scheme.generateDecryptionKey(msk, invalidPolicy);

        SetOfAttributes validPublicAttributes = new SetOfAttributes();
        validPublicAttributes.add(attributes[0]);
        validPublicAttributes.add(attributes[3]);
        validPublicAttributes.add(attributes[4]);

        EncryptionKey validPK = scheme.generateEncryptionKey(validPublicAttributes);

        KeyPair validKeyPair = new KeyPair(validPK, validSK);
        KeyPair invalidKeyPair = new KeyPair(validPK, invalidSK);

        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()));
        return new TestParams(scheme, supplier, validKeyPair, invalidKeyPair);
    }
}
