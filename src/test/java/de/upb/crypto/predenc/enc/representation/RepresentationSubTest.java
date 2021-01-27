package de.upb.crypto.predenc.enc.representation;

import de.upb.crypto.craco.enc.representation.RepresentationTest;
import de.upb.crypto.craco.enc.representation.RepresentationTestParams;
import de.upb.crypto.predenc.enc.representation.params.*;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;

public class RepresentationSubTest extends RepresentationTest {
    public RepresentationSubTest(RepresentationTestParams params) {
        super(params);
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<RepresentationTestParams> data() {
        ArrayList<RepresentationTestParams> toReturn = new ArrayList<>();
        toReturn.add(ABEKPGPSW06SmallParams.getParams());
        toReturn.add(ABECPWat11SmallParams.getParams());
        toReturn.add(ABECPWat11Params.getParams());
        toReturn.add(ABEKPGPSW06Params.getParams());
        toReturn.add(IBEFuzzySW05SmallParams.getParams());
        toReturn.add(IBEFuzzySW05Params.getParams());
        toReturn.add(FullIdentParams.getParams());
        toReturn.add(ABECPWat11AsymSmallParams.getParams());
        return toReturn;
    }
}
