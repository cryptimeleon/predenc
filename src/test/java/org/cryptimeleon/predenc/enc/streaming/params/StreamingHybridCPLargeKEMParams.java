package org.cryptimeleon.predenc.enc.streaming.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.enc.*;
import org.cryptimeleon.craco.enc.streaming.StreamingEncryptionSchemeParams;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingCBCAES;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAES;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanism;
import org.cryptimeleon.craco.kem.StreamingHybridEncryptionScheme;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11MasterSecret;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11PublicParameters;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;
import org.cryptimeleon.predenc.kem.abe.cp.large.ABECPWat11KEM;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class StreamingHybridCPLargeKEMParams {

    public static Collection<StreamingEncryptionSchemeParams> get() {
        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number
        // of lines in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);

        ABECPWat11PublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11MasterSecret msk = setup.getMasterSecret();
        ABECPWat11 largeScheme = new ABECPWat11(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));

        ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E"));

        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey pk = largeScheme.generateEncryptionKey((CiphertextIndex) policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(new StringAttribute("A"));
        validAttributes.add(new StringAttribute("D"));
        validAttributes.add(new StringAttribute("E"));

        DecryptionKey validSK = largeScheme.generateDecryptionKey(msk, validAttributes);

        EncryptionKeyPair keyPair = new EncryptionKeyPair(pk, validSK);
        StreamingEncryptionScheme streamingAESGCMPacketMode = new StreamingGCMAESPacketMode();
        StreamingEncryptionScheme streamingAESGCMScheme = new StreamingGCMAES();
        StreamingEncryptionScheme streamingAESCBCScheme = new StreamingCBCAES();
        KeyEncapsulationMechanism<SymmetricKey> kem = new SymmetricKeyPredicateKEM(new ABECPWat11KEM(publicParams),
                new HashBasedKeyDerivationFunction());

        StreamingHybridEncryptionScheme hybridAESGCMPacketModeScheme = new StreamingHybridEncryptionScheme(
                streamingAESGCMPacketMode, kem);
        StreamingHybridEncryptionScheme hybridAESGCMScheme = new StreamingHybridEncryptionScheme(streamingAESGCMScheme,
                kem);
        StreamingHybridEncryptionScheme hybridAESCBCScheme = new StreamingHybridEncryptionScheme(streamingAESCBCScheme,
                kem);

        List<StreamingEncryptionSchemeParams> toReturn = new ArrayList<>();
        toReturn.add(new StreamingEncryptionSchemeParams(hybridAESGCMPacketModeScheme, keyPair));
        toReturn.add(new StreamingEncryptionSchemeParams(hybridAESGCMScheme, keyPair));
        toReturn.add(new StreamingEncryptionSchemeParams(hybridAESCBCScheme, keyPair));
        return toReturn;
    }

}
