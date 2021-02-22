package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.predenc.abe.ibe.FullIdent;
import org.cryptimeleon.predenc.abe.ibe.FullIdentKEM;
import org.cryptimeleon.predenc.abe.ibe.FullIdentPublicParameters;
import org.cryptimeleon.predenc.abe.ibe.FullIdentSetup;

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
