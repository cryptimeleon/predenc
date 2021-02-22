package org.cryptimeleon.predenc.enc.representation.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.representation.RepresentationTestParams;
import org.cryptimeleon.predenc.abe.kp.large.*;
import org.cryptimeleon.predenc.enc.representation.PredEncRepresentationTestParams;

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