package org.cryptimeleon.predenc.enc.params;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.KeyPair;
import org.cryptimeleon.craco.enc.TestParams;
import org.cryptimeleon.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import org.cryptimeleon.predenc.abe.ibe.FullIdent;
import org.cryptimeleon.predenc.abe.ibe.FullIdentMasterSecret;
import org.cryptimeleon.predenc.abe.ibe.FullIdentPublicParameters;
import org.cryptimeleon.predenc.abe.ibe.FullIdentSetup;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Supplier;

public class FullIdentParams {

    public static TestParams getParams() {
        try {
            FullIdentSetup setup = new FullIdentSetup();

            setup.doKeyGen(80, BigInteger.valueOf(1024), true);

            FullIdentPublicParameters pp = setup.getPublicParameters();

            FullIdentMasterSecret msk = setup.getMasterSecret();

            FullIdent fi = new FullIdent(pp);

            Supplier<PlainText> supplier = new FullIdentSupplier();


            ByteArrayImplementation identity = new ByteArrayImplementation("mirkoj@mail.upb.de".getBytes("UTF-8"));

            DecryptionKey privateKey = fi.generateDecryptionKey(msk, identity);
            EncryptionKey publicKey = fi.generateEncryptionKey(identity);

            ByteArrayImplementation corruptedIdentity = new ByteArrayImplementation(
                    "schuerma@mail.upb.de".getBytes("UTF-8"));
            DecryptionKey corruptedPrivateKey = fi.generateDecryptionKey(msk, corruptedIdentity);

            KeyPair validKeyPair = new KeyPair(publicKey, privateKey);
            KeyPair invalidKeyPair = new KeyPair(publicKey, corruptedPrivateKey);

            return new TestParams(fi, supplier, validKeyPair, invalidKeyPair);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static class FullIdentSupplier implements Supplier<PlainText> {

        SecureRandom random = new SecureRandom();

        @Override
        public PlainText get() {
            byte[] toReturn = new byte[1024];
            random.nextBytes(toReturn);
            return new ByteArrayImplementation(toReturn);
        }

    }
}
