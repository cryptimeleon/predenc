package org.cryptimeleon.predenc.enc;

import org.cryptimeleon.craco.enc.EncryptionSchemeTest;
import org.cryptimeleon.craco.enc.TestParams;
import org.cryptimeleon.predenc.enc.params.*;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;

public class EncryptionSchemeSubTest extends EncryptionSchemeTest {
    public EncryptionSchemeSubTest(TestParams params) {
        super(params);
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<TestParams> data() {
        ArrayList<TestParams> schemes = new ArrayList<>();
        //non generic schemes
        schemes.add(IBEFuzzySW05SmallParams.getParams());
        schemes.add(IBEFuzzySW05Params.getParams());
        schemes.add(FullIdentParams.getParams());
        //generic schemes
        schemes.addAll(ABECPWat11Params.getParams());
        schemes.addAll(ABECPWat11SmallParams.getParams());
        schemes.addAll(ABEKPGPSW06Params.getParams());
        schemes.addAll(DistributedABECPWat11Params.getParams());
        schemes.addAll(ABECPWat11AsymSmallParams.getParams());
        return schemes;
    }
}
