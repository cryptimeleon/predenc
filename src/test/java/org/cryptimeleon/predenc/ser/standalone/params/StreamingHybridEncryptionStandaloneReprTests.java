package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.enc.StreamingEncryptionScheme;
import org.cryptimeleon.craco.enc.SymmetricKey;
import org.cryptimeleon.craco.enc.sym.streaming.aes.StreamingGCMAESPacketMode;
import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanism;
import org.cryptimeleon.craco.kem.StreamingHybridEncryptionScheme;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;
import org.cryptimeleon.predenc.kem.abe.cp.large.ABECPWat11KEM;

public class StreamingHybridEncryptionStandaloneReprTests extends StandaloneReprSubTest {
    public void testStreamingHybridEncryptionScheme() {
        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number
        // of lines in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);

        KeyEncapsulationMechanism<SymmetricKey> kem = new SymmetricKeyPredicateKEM(
                new ABECPWat11KEM(setup.getPublicParameters()), new HashBasedKeyDerivationFunction());
        StreamingEncryptionScheme streamingAESGCMPacketMode = new StreamingGCMAESPacketMode();

        StreamingHybridEncryptionScheme hybridAESGCMPacketModeScheme = new StreamingHybridEncryptionScheme(
                streamingAESGCMPacketMode, kem);
        test(hybridAESGCMPacketModeScheme);
    }
}
