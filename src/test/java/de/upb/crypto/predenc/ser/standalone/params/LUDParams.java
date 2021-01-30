package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.StringAttribute;
import de.upb.crypto.craco.common.policies.BooleanPolicy;
import de.upb.crypto.craco.common.policies.BooleanPolicy.BooleanOperator;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.predenc.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import de.upb.crypto.predenc.kem.abe.cp.os.LUDEncryptionKey;
import de.upb.crypto.predenc.kem.abe.cp.os.LUDPublicParameters;
import de.upb.crypto.predenc.kem.abe.cp.os.LUDSetup;

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
