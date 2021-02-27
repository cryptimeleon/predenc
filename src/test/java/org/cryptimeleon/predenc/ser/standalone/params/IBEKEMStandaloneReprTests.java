package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.ibe.FullIdent;
import org.cryptimeleon.predenc.abe.ibe.FullIdentKEM;
import org.cryptimeleon.predenc.abe.ibe.FullIdentSetup;

import java.math.BigInteger;

public class IBEKEMStandaloneReprTests extends StandaloneReprSubTest {

    public void testFullIdentKem() {
        FullIdentSetup setup = new FullIdentSetup();
        setup.doKeyGen(80, BigInteger.valueOf(10), true);
        FullIdent large = new FullIdent(setup.getPublicParameters());
        test(new FullIdentKEM(large));
    }
}
