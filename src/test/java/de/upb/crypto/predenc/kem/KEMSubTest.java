package de.upb.crypto.predenc.kem;

import de.upb.crypto.craco.kem.KeyEncapsulationMechanismTest;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanismTestParams;
import de.upb.crypto.predenc.kem.params.ABECPWat11KEMParams;
import de.upb.crypto.predenc.kem.params.ABEKPGPSW06KEMParams;
import de.upb.crypto.predenc.kem.params.ElgamalLargeDelegKEMParams;
import de.upb.crypto.predenc.kem.params.IBEFuzzySW05KEMParams;
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
