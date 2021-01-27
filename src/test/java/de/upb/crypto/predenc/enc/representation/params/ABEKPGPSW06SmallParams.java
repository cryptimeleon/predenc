package de.upb.crypto.predenc.enc.representation.params;

import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.abe.kp.small.*;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.common.policy.Policy;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;

import java.util.HashSet;
import java.util.Set;

public class ABEKPGPSW06SmallParams {
    public static RepresentationTestParams getParams() {
        Set<StringAttribute> universe = new HashSet<>();
        universe.add(new StringAttribute("A"));
        universe.add(new StringAttribute("B"));
        universe.add(new StringAttribute("C"));
        universe.add(new StringAttribute("D"));
        universe.add(new StringAttribute("E"));

        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();
        setup.doKeyGen(80, universe, true);

        ABEKPGPSW06SmallMasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06SmallPublicParameters publicParams = setup.getPublicParameters();

        ABEKPGPSW06Small scheme = new ABEKPGPSW06Small(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));

        ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E"));

        Policy validPolicy = new ThresholdPolicy(2, leftNode, rightNode);
        DecryptionKey validSK = scheme.generateDecryptionKey(msk, validPolicy);

        SetOfAttributes validPublicAttributes = new SetOfAttributes();
        validPublicAttributes.add(new StringAttribute("A"));
        validPublicAttributes.add(new StringAttribute("D"));
        validPublicAttributes.add(new StringAttribute("E"));

        EncryptionKey validPK = (ABEKPGPSW06SmallEncryptionKey) scheme.generateEncryptionKey(validPublicAttributes);

        PlainText plaintext = new GroupElementPlainText(publicParams.getGroupGT().getUniformlyRandomElement());

        CipherText ciphertext = (ABEKPGPSW06SmallCipherText) scheme.encrypt(plaintext, validPK);
        return new RepresentationTestParams(scheme, validPK, validSK, plaintext, ciphertext, msk);

    }
}
