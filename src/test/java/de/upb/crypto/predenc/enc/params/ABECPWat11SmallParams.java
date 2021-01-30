package de.upb.crypto.predenc.enc.params;

import de.upb.crypto.craco.common.attributes.Attribute;
import de.upb.crypto.craco.common.attributes.BigIntegerAttribute;
import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.common.plaintexts.GroupElementPlainText;
import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.common.policies.BooleanPolicy;
import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.common.policies.ThresholdPolicy;
import de.upb.crypto.craco.common.predicate.KeyIndex;
import de.upb.crypto.craco.enc.*;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11Small;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11SmallMasterSecret;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11SmallPublicParameters;
import de.upb.crypto.predenc.abe.cp.small.ABECPWat11SmallSetup;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Supplier;

public class ABECPWat11SmallParams {
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

        ABECPWat11SmallSetup setup = new ABECPWat11SmallSetup();

        setup.doKeyGen(80, Arrays.asList(attributes), true);

        ABECPWat11SmallPublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11SmallMasterSecret msk = setup.getMasterSecret();
        ABECPWat11Small smallScheme = new ABECPWat11Small(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);

        BooleanPolicy bleftNode = new BooleanPolicy(BooleanPolicy.BooleanOperator.OR, attributes[0], attributes[1]);

        BooleanPolicy bright2 = new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, attributes[3], attributes[4]);


        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

        Policy bPolicy = new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, bleftNode, bright2);
        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey validPK = smallScheme.generateEncryptionKey(bPolicy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(attributes[0]);
        validAttributes.add(attributes[3]);
        validAttributes.add(attributes[4]);

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(attributes[0]);
        invalidAttributes.add(attributes[3]);

        DecryptionKey validSK = smallScheme.generateDecryptionKey(msk, validAttributes);
        DecryptionKey invalidSK = smallScheme.generateDecryptionKey(msk, invalidAttributes);

        KeyPair validKeyPair = new KeyPair(validPK, validSK);
        KeyPair invalidKeyPair = new KeyPair(validPK, invalidSK);

        Supplier<PlainText> abeCPSmallSupplier = () -> ((PlainText) new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()));

        return new TestParams(((EncryptionScheme) smallScheme), abeCPSmallSupplier, validKeyPair, invalidKeyPair);

    }

}
