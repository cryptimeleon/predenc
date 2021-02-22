package org.cryptimeleon.predenc.kem;

import org.cryptimeleon.craco.kem.KeyEncapsulationMechanismTest;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanismTestParams;
import org.cryptimeleon.predenc.kem.params.ABECPWat11KEMParams;
import org.cryptimeleon.predenc.kem.params.ABEKPGPSW06KEMParams;
import org.cryptimeleon.predenc.kem.params.ElgamalLargeDelegKEMParams;
import org.cryptimeleon.predenc.kem.params.IBEFuzzySW05KEMParams;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;

public class KEMSubTest extends KeyEncapsulationMechanismTest {

    public KEMSubTest(KeyEncapsulationMechanismTestParams params) {
        super(params);
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<KeyEncapsulationMechanismTestParams> data() {
        ArrayList<KeyEncapsulationMechanismTestParams> schemes = new ArrayList<>();
        schemes.addAll(ABECPWat11KEMParams.getParams());
        schemes.addAll(IBEFuzzySW05KEMParams.getParams());
        schemes.addAll(ABEKPGPSW06KEMParams.getParams());
        schemes.addAll(ElgamalLargeDelegKEMParams.getParams());
        return schemes;
    }
}
