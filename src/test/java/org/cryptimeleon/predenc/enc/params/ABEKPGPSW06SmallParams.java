package org.cryptimeleon.predenc.enc.params;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKeyPair;
import org.cryptimeleon.craco.enc.TestParams;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06Small;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallMasterSecret;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallPublicParameters;
import org.cryptimeleon.predenc.abe.kp.small.ABEKPGPSW06SmallSetup;

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

        EncryptionKeyPair validKeyPair = new EncryptionKeyPair(validPK, validSK);
        EncryptionKeyPair invalidKeyPair = new EncryptionKeyPair(validPK, invalidSK);

        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()));
        return new TestParams(scheme, supplier, validKeyPair, invalidKeyPair);
    }
}
