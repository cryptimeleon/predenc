package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.BooleanPolicy;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDEncryptionKey;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDSetup;

public class LUDKEMStandaloneReprTests extends StandaloneReprSubTest {

    ElgamalLargeUniverseDelegationKEM ludkem;
    LUDEncryptionKey key;
    LUDSetup schemeFactory;

    public LUDKEMStandaloneReprTests() {
        BilinearGroup group = new DebugBilinearGroup(80, BilinearGroup.Type.TYPE_3);
        schemeFactory = new LUDSetup();
        schemeFactory.setup(group, new SHA256HashFunction());
        ludkem = new ElgamalLargeUniverseDelegationKEM(
                schemeFactory.getPublicParameters());
        key = ludkem.generateEncryptionKey(
                new BooleanPolicy(
                        BooleanPolicy.BooleanOperator.AND, new StringAttribute("A"), new StringAttribute("B")
                )
        );
    }

    public void testScheme() {
        test(ludkem);
    }

    public void testPublicParameters() {
        test(schemeFactory.getPublicParameters());
    }

    public void testLUDKemKey() {
        test(key);
    }
}
