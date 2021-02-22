package org.cryptimeleon.predenc.enc.representation;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.EncryptionScheme;
import org.cryptimeleon.craco.enc.representation.RepresentationTestParams;
import org.cryptimeleon.predenc.MasterSecret;

public class PredEncRepresentationTestParams extends RepresentationTestParams {
    protected MasterSecret masterSecret;

    public PredEncRepresentationTestParams(EncryptionScheme scheme, EncryptionKey encryptionKey,
                                           DecryptionKey decryptionKey, PlainText plainText,
                                           CipherText cipherText, MasterSecret masterSecret) {
        super(scheme, encryptionKey, decryptionKey, plainText, cipherText);
        this.masterSecret = masterSecret;
    }


    public String toString() {
        return scheme.getClass().getName();
    }
}
