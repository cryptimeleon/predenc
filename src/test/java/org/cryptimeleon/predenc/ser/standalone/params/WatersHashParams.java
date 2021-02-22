package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.WatersHash;

public class WatersHashParams {
    public static StandaloneTestParams get() {
        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_1);
        return new StandaloneTestParams(WatersHash.class, new WatersHash(group.getG1(), 10));
    }
}
