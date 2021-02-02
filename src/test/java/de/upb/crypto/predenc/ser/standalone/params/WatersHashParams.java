package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.predenc.WatersHash;

public class WatersHashParams {
    public static StandaloneTestParams get() {
        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_1);
        return new StandaloneTestParams(WatersHash.class, new WatersHash(group.getG1(), 10));
    }
}
