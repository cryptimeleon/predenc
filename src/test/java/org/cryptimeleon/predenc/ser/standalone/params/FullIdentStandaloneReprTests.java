package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.ibe.FullIdent;
import org.cryptimeleon.predenc.abe.ibe.FullIdentSetup;
import org.cryptimeleon.predenc.kem.ibe.FullIdentKEM;

import java.math.BigInteger;

public class FullIdentStandaloneReprTests extends StandaloneReprSubTest {

    FullIdentSetup setup;

    public FullIdentStandaloneReprTests() {
        setup = new FullIdentSetup();
        setup.doKeyGen(80, BigInteger.valueOf(10), true);
    }

    public void testFullIdent() {
        test(new FullIdent(setup.getPublicParameters()));
    }

    public void testPublicParameters() {
        test(setup.getPublicParameters());
    }

    public void testKem() {
        test(new FullIdentKEM(new FullIdent(setup.getPublicParameters())));
    }
}
