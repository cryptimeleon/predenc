package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.WatersHash;

public class WatersHashStandaloneReprTests extends StandaloneReprSubTest {

    public void testWatersHash() {
        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_1);
        test(new WatersHash(group.getG1(), 10));
    }
}
