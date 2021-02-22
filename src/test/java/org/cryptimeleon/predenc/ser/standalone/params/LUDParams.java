package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.BooleanPolicy;
import org.cryptimeleon.craco.common.policies.BooleanPolicy.BooleanOperator;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.predenc.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDEncryptionKey;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDPublicParameters;
import org.cryptimeleon.predenc.kem.abe.cp.os.LUDSetup;

import java.util.ArrayList;
import java.util.Collection;

public class LUDParams {

    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        BilinearGroup group = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_3);
        LUDSetup schemeFactory;

        schemeFactory = new LUDSetup();

        schemeFactory.setup(group, new SHA256HashFunction());

        toReturn.add(new StandaloneTestParams(LUDPublicParameters.class, schemeFactory.getPublicParameters()));
        ElgamalLargeUniverseDelegationKEM ludkem = new ElgamalLargeUniverseDelegationKEM(
                schemeFactory.getPublicParameters());
        toReturn.add(new StandaloneTestParams(ElgamalLargeUniverseDelegationKEM.class, ludkem));
        LUDEncryptionKey key = ludkem.generateEncryptionKey(
                new BooleanPolicy(BooleanOperator.AND, new StringAttribute("A"), new StringAttribute("B")));
        toReturn.add(new StandaloneTestParams(LUDEncryptionKey.class, key));

        return toReturn;
    }

}
