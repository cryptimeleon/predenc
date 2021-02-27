package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11MasterKeyShare;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11Setup;

public class DistributedABECPWat11StandaloneReprTests extends StandaloneReprSubTest {

    DistributedABECPWat11 scheme;
    DistributedABECPWat11Setup setup;

    public DistributedABECPWat11StandaloneReprTests() {
        DistributedABECPWat11Setup setup = new DistributedABECPWat11Setup();
        setup.doKeyGen(80, 5, 4, 2, 2, true);
        scheme = new DistributedABECPWat11(setup.getPublicParameters());
    }

    public void testScheme() {
        test(scheme);
    }

    public void testMasterKeyShare() {
        test(setup.getMasterKeyShares().iterator().next());
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }
}
