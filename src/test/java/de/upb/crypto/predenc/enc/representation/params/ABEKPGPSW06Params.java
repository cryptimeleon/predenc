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
import de.upb.crypto.predenc.abe.kp.large.*;
import de.upb.crypto.predenc.enc.representation.PredEncRepresentationTestParams;

public class ABEKPGPSW06Params {
    public static RepresentationTestParams getParams() {

        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 10, false, true);

        ABEKPGPSW06MasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06PublicParameters publicParams = setup.getPublicParameters();

        ABEKPGPSW06 scheme = new ABEKPGPSW06(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));

        ThresholdPolicy rightNode = new ThresholdPolicy(2,
                new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E")
        );

        Policy validPolicy = new ThresholdPolicy(2, leftNode, rightNode);
        DecryptionKey validSK = scheme.generateDecryptionKey(msk, validPolicy);

        SetOfAttributes validPublicAttributes = new SetOfAttributes();
        validPublicAttributes.add(new StringAttribute("A"));
        validPublicAttributes.add(new StringAttribute("D"));
        validPublicAttributes.add(new StringAttribute("E"));

        EncryptionKey validPK = scheme.generateEncryptionKey(validPublicAttributes);

        PlainText plaintext = new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement());

        CipherText ciphertext = scheme.encrypt(plaintext, validPK);

        return new PredEncRepresentationTestParams(scheme, validPK, validSK, plaintext, ciphertext, msk);
    }
}