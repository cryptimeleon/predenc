package org.cryptimeleon.predenc.ser.standalone;

import org.cryptimeleon.craco.ser.standalone.StandaloneTest;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.predenc.ser.standalone.params.*;
import org.junit.runners.Parameterized;
import org.reflections.Reflections;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

public class StandaloneSubTest extends StandaloneTest {

    public StandaloneSubTest(StandaloneTestParams params) {
        super(params);
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<StandaloneTestParams> getStandaloneClasses() {
        Reflections reflection = new Reflections("org.cryptimeleon.predenc");
        // get all classes that are subtypes of standalone representable
        Set<Class<? extends StandaloneRepresentable>> classes = reflection.getSubTypesOf(StandaloneRepresentable.class);
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        // add org.cryptimeleon.groupsig.params here
        System.out.println("Creating objects that will be serialized...");
        toReturn.addAll(ABECPWat11Params.get());
        toReturn.addAll(ABECPWat11SmallParams.get());
        toReturn.addAll(DistributedABECPWat11Params.get());
        toReturn.addAll(ABEKPGPSW06Params.get());
        toReturn.addAll(ABEKPGPSW06SmallParams.get());
        toReturn.addAll(IBEFuzzySW05Params.get());
        toReturn.addAll(IBEFuzzySW05SmallParams.get());
        toReturn.addAll(FullIdentParams.get());
        toReturn.add(IdentityParams.get());
        toReturn.add(ABECPWat11KEMParams.get());
        toReturn.add(ABECPWat11SymmetricKEMParams.get());
        toReturn.addAll(LUDParams.get());
        toReturn.addAll(ABECPWat11AsymSmallParams.get());
        toReturn.add(StreamingHybridEncryptionSchemeParams.get());
        toReturn.add(WatersHashParams.get());

        System.out.println("Finished creating objects...");
        // remove all provided params
        for (StandaloneTestParams stp : toReturn) {
            classes.remove(stp.toTest);
        }
        // add remaining classes
        for (Class<? extends StandaloneRepresentable> c : classes) {
            if (!c.isInterface() && !Modifier.isAbstract(c.getModifiers())) {
                toReturn.add(new StandaloneTestParams(c, null));
            }
        }

        return toReturn;
    }
}
