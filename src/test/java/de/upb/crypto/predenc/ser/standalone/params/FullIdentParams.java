package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.predenc.abe.ibe.FullIdent;
import de.upb.crypto.predenc.abe.ibe.FullIdentKEM;
import de.upb.crypto.predenc.abe.ibe.FullIdentPublicParameters;
import de.upb.crypto.predenc.abe.ibe.FullIdentSetup;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class FullIdentParams {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        FullIdentSetup setup = new FullIdentSetup();
        setup.doKeyGen(80, BigInteger.valueOf(10), true);
        toReturn.add(new StandaloneTestParams(FullIdentPublicParameters.class, setup.getPublicParameters()));
        FullIdent large = new FullIdent(setup.getPublicParameters());
        FullIdentKEM kem = new FullIdentKEM(large);
        toReturn.add(new StandaloneTestParams(FullIdent.class, large));
        toReturn.add(new StandaloneTestParams(FullIdentKEM.class, kem));
        return toReturn;
    }

}
