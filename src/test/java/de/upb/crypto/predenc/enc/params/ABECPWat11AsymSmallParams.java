package de.upb.crypto.predenc.enc.params;

import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmall;
import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmallMasterSecret;
import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmallPublicParameters;
import de.upb.crypto.predenc.abe.cp.small.asymmetric.ABECPWat11AsymSmallSetup;
import de.upb.crypto.predenc.abe.interfaces.Attribute;
import de.upb.crypto.predenc.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.predenc.abe.interfaces.SetOfAttributes;
import de.upb.crypto.predenc.abe.interfaces.StringAttribute;

import java.util.ArrayList;
import java.util.Arrays;

public class ABECPWat11AsymSmallParams {
    public static ArrayList<de.upb.crypto.craco.enc.test.TestParams> getParams() {
        Attribute[] stringAttributes = {new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")};
        de.upb.crypto.craco.enc.test.TestParams stringAttrParams = createGenericParams(stringAttributes);
        Attribute[] integerAttribute =
                {new BigIntegerAttribute(0), new BigIntegerAttribute(1), new BigIntegerAttribute(2),
                        new BigIntegerAttribute(3), new BigIntegerAttribute(4)};
        de.upb.crypto.craco.enc.test.TestParams integerAttrParams = createGenericParams(integerAttribute);

        ArrayList<de.upb.crypto.craco.enc.test.TestParams> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }

    private static de.upb.crypto.craco.enc.test.TestParams createGenericParams(Attribute[] attributes) {

        ABECPWat11AsymSmallSetup setup = new ABECPWat11AsymSmallSetup();

        setup.doKeyGen(80, Arrays.asList(attributes), true);

        ABECPWat11AsymSmallPublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11AsymSmallMasterSecret msk = setup.getMasterSecret();
        ABECPWat11AsymSmall smallScheme = new ABECPWat11AsymSmall(publicParams);

        de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy leftNode = new de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy(1, attributes[0], attributes[1]);

        de.upb.crypto.craco.secretsharing.policy.BooleanPolicy bleftNode = new de.upb.crypto.craco.secretsharing.policy.BooleanPolicy(de.upb.crypto.craco.secretsharing.policy.BooleanPolicy.BooleanOperator.OR, attributes[0], attributes[1]);

        de.upb.crypto.craco.secretsharing.policy.BooleanPolicy bright2 = new de.upb.crypto.craco.secretsharing.policy.BooleanPolicy(de.upb.crypto.craco.secretsharing.policy.BooleanPolicy.BooleanOperator.AND, attributes[3], attributes[4]);


        de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy rightNode = new de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

        Policy bPolicy = new de.upb.crypto.craco.secretsharing.policy.BooleanPolicy(de.upb.crypto.craco.secretsharing.policy.BooleanPolicy.BooleanOperator.AND, bleftNode, bright2);
        Policy policy = new de.upb.crypto.craco.secretsharing.policy.ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey validPK = smallScheme.generateEncryptionKey(bPolicy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(attributes[0]);
        validAttributes.add(attributes[3]);
        validAttributes.add(attributes[4]);

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(attributes[0]);
        invalidAttributes.add(attributes[3]);

        de.upb.crypto.craco.enc.DecryptionKey validSK = smallScheme.generateDecryptionKey(msk, validAttributes);
        de.upb.crypto.craco.enc.DecryptionKey invalidSK = smallScheme.generateDecryptionKey(msk, invalidAttributes);

        KeyPair validKeyPair = new KeyPair(validPK, validSK);
        KeyPair invalidKeyPair = new KeyPair(validPK, invalidSK);

        Supplier<de.upb.crypto.craco.common.PlainText> abeCPSmallSupplier = () -> ((de.upb.crypto.craco.common.PlainText) new de.upb.crypto.craco.common.GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()));

        return new de.upb.crypto.craco.enc.test.TestParams(smallScheme, abeCPSmallSupplier, validKeyPair, invalidKeyPair);
    }
}
