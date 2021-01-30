package de.upb.crypto.predenc.kem.params;

import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.enc.KeyPair;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanismTestParams;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.predenc.kem.ElgamalLargeUniverseDelegationKEMTest;
import de.upb.crypto.predenc.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import de.upb.crypto.predenc.kem.abe.cp.os.LUDDecryptionKey;
import de.upb.crypto.predenc.kem.abe.cp.os.LUDEncryptionKey;
import de.upb.crypto.predenc.kem.abe.cp.os.LUDSetup;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ElgamalLargeDelegKEMParams {
	public static List<KeyEncapsulationMechanismTestParams> getParams() {
		BilinearGroup bilinearGroup = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_3);

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

		KeyPair validKeyPair = new KeyPair(encKey, dkSatisfy);
		KeyPair invalidKeyPair = new KeyPair(encKey, dkNonSatisfy);

		return Stream.of(
				new KeyEncapsulationMechanismTestParams(scheme, validKeyPair, invalidKeyPair)
		).collect(Collectors.toList());
	}
}
