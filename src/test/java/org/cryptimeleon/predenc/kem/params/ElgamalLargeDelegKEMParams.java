package org.cryptimeleon.predenc.kem.params;

import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.enc.EncryptionKeyPair;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanismTestParams;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.kem.ElgamalLargeUniverseDelegationKEMTest;
import org.cryptimeleon.predenc.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDDecryptionKey;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDEncryptionKey;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDSetup;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ElgamalLargeDelegKEMParams {
	public static List<KeyEncapsulationMechanismTestParams> getParams() {
		BilinearGroup bilinearGroup = new DebugBilinearGroup(RandomGenerator.getRandomPrime(80), BilinearGroup.Type.TYPE_3);

		LUDSetup schemeFactory;
		schemeFactory = new LUDSetup();
		schemeFactory.setup(bilinearGroup, new SHA256HashFunction());
		ElgamalLargeUniverseDelegationKEM scheme = schemeFactory.getScheme();

		Policy policy = ElgamalLargeUniverseDelegationKEMTest.setupPolicy();

		LUDEncryptionKey encKey = scheme.generateEncryptionKey(policy);
		/*
		 * generate satifying and non-satisfying decryption keys for policy
		 */
		LUDDecryptionKey dkSatisfy = scheme.generateDecryptionKey(
				schemeFactory.getMasterSecretKey(), ElgamalLargeUniverseDelegationKEMTest.getFulfilling()
		);
		LUDDecryptionKey dkNonSatisfy = scheme.generateDecryptionKey(
				schemeFactory.getMasterSecretKey(), ElgamalLargeUniverseDelegationKEMTest.getNonFulfilling()
		);

		EncryptionKeyPair validKeyPair = new EncryptionKeyPair(encKey, dkSatisfy);
		EncryptionKeyPair invalidKeyPair = new EncryptionKeyPair(encKey, dkNonSatisfy);

		return Stream.of(
				new KeyEncapsulationMechanismTestParams(scheme, validKeyPair, invalidKeyPair)
		).collect(Collectors.toList());
	}
}
