package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.ibe.FullIdent;
import org.cryptimeleon.predenc.abe.ibe.FullIdentPublicParameters;
import org.cryptimeleon.predenc.abe.ibe.FullIdentSetup;

import java.math.BigInteger;

public class IBEStandaloneReprTests extends StandaloneReprSubTest {

    public void testFullIdent() {
        FullIdentSetup setup = new FullIdentSetup();
        setup.doKeyGen(80, BigInteger.valueOf(10), true);
        test(new FullIdent(setup.getPublicParameters()));
    }
}
