package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.BooleanPolicy;
import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.abe.cp.large.ABECPWat11Setup;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11Small;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11SmallKEM;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11SmallSetup;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;
import org.cryptimeleon.predenc.kem.abe.cp.large.ABECPWat11KEM;
import org.cryptimeleon.predenc.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDEncryptionKey;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDSetup;

public class ABECPKEMStandaloneReprTests extends StandaloneReprSubTest {

    public void testCpLargeKem() {
        ABECPWat11Setup setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
        test(new ABECPWat11KEM(setup.getPublicParameters()));
    }

    public void testCpSmallKem() {
        ABECPWat11SmallSetup setup = new ABECPWat11SmallSetup();
        SetOfAttributes universe =
                new SetOfAttributes(new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                        new StringAttribute("D"), new StringAttribute("E"));
        setup.doKeyGen(80, universe, true);
        ABECPWat11Small small = new ABECPWat11Small(setup.getPublicParameters());
        test(new ABECPWat11SmallKEM(small));
    }

    public void testCpLargeSymmetricKem() {
        final int securityParameter = 60;

        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number of attributes in the MSP)
        setup.doKeyGen(securityParameter, 5, 5, false, true);

        ABECPWat11KEM scheme = new ABECPWat11KEM(setup.getPublicParameters());
        HashBasedKeyDerivationFunction kdf = new HashBasedKeyDerivationFunction();
        test(new SymmetricKeyPredicateKEM(scheme, kdf));
    }

    public void testLUDKem() {
        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_3);
        LUDSetup schemeFactory;
        schemeFactory = new LUDSetup();
        schemeFactory.setup(group, new SHA256HashFunction());
        ElgamalLargeUniverseDelegationKEM ludkem = new ElgamalLargeUniverseDelegationKEM(
                schemeFactory.getPublicParameters());
        test(ludkem);
    }

    public void testLUDKemKey() {
        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_3);
        LUDSetup schemeFactory;
        schemeFactory = new LUDSetup();
        schemeFactory.setup(group, new SHA256HashFunction());
        ElgamalLargeUniverseDelegationKEM ludkem = new ElgamalLargeUniverseDelegationKEM(
                schemeFactory.getPublicParameters());
        LUDEncryptionKey key = ludkem.generateEncryptionKey(
                new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, new StringAttribute("A"), new StringAttribute("B"))
        );
        test(key);
    }
}
