package de.upb.crypto.predenc.enc.representation.params;

import de.upb.crypto.craco.common.attributes.SetOfAttributes;
import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.common.plaintexts.GroupElementPlainText;
import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.common.policies.ThresholdPolicy;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.representation.RepresentationTestParams;
import de.upb.crypto.predenc.abe.cp.large.*;
import de.upb.crypto.predenc.enc.representation.PredEncRepresentationTestParams;

public class ABECPWat11Params {

    public static RepresentationTestParams getParams() {
        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max length)
        setup.doKeyGen(80, 5, 5, false, true);

        ABECPWat11PublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11MasterSecret msk = setup.getMasterSecret();
        ABECPWat11 largeScheme = new ABECPWat11(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode =
                new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));

        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey pk = largeScheme.generateEncryptionKey(policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(new StringAttribute("A"));
        validAttributes.add(new StringAttribute("D"));
        validAttributes.add(new StringAttribute("E"));

        DecryptionKey validSK = largeScheme.generateDecryptionKey(msk, validAttributes);

        PlainText plaintext = new GroupElementPlainText(publicParams.getGroupGT().getUniformlyRandomElement());

        CipherText ciphertext = largeScheme.encrypt(plaintext, pk);

        return new PredEncRepresentationTestParams(largeScheme, pk, validSK, plaintext, ciphertext, msk);
    }
}
