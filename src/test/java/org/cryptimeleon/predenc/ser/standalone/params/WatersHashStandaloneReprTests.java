package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.WatersHash;

public class WatersHashStandaloneReprTests extends StandaloneReprSubTest {

    public void testWatersHash() {
        BilinearGroup group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(80), BilinearGroup.Type.TYPE_1);
        test(new WatersHash(group.getG1(), 10));
    }
}
