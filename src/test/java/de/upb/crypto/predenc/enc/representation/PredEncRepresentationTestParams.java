package de.upb.crypto.predenc.enc.representation;

import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.EncryptionScheme;
import de.upb.crypto.craco.enc.representation.RepresentationTestParams;
import de.upb.crypto.predenc.MasterSecret;

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
