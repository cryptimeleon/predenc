package org.cryptimeleon.predenc.enc.representation.params;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.representation.RepresentationTestParams;
import org.cryptimeleon.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import org.cryptimeleon.predenc.abe.ibe.FullIdent;
import org.cryptimeleon.predenc.abe.ibe.FullIdentMasterSecret;
import org.cryptimeleon.predenc.abe.ibe.FullIdentPublicParameters;
import org.cryptimeleon.predenc.abe.ibe.FullIdentSetup;
import org.cryptimeleon.predenc.enc.representation.PredEncRepresentationTestParams;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class FullIdentParams {
    public static RepresentationTestParams getParams() {

        byte[] stringPlaintext;
        try {
            stringPlaintext = "keine Ahnung".getBytes("UTF-8");

            PlainText pt = new ByteArrayImplementation(stringPlaintext);

            FullIdentSetup setup = new FullIdentSetup();

            setup.doKeyGen(80, BigInteger.valueOf(stringPlaintext.length), true);

            FullIdentPublicParameters pp = setup.getPublicParameters();

            FullIdentMasterSecret msk = setup.getMasterSecret();

            FullIdent fi = new FullIdent(pp);

            ByteArrayImplementation identity = new ByteArrayImplementation("mirkoj@mail.upb.de".getBytes("UTF-8"));

            DecryptionKey privateKey = fi.generateDecryptionKey(msk, identity);
            EncryptionKey publicKey = fi.generateEncryptionKey(identity);

            CipherText ct = fi.encrypt(pt, publicKey);

            return new PredEncRepresentationTestParams(fi, publicKey, privateKey, pt, ct, msk);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }

    }
}
