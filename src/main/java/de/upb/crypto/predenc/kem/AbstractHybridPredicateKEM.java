package de.upb.crypto.predenc.kem;

import de.upb.crypto.craco.common.de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.de.upb.crypto.craco.interfaces.EncryptionScheme;
import de.upb.crypto.craco.common.de.upb.crypto.craco.interfaces.SymmetricKey;
import de.upb.crypto.craco.common.de.upb.crypto.craco.interfaces.pe.PredicateKEM;
import de.upb.crypto.craco.kem.AbstractHybridConstructionKEM;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;

/**
 * A KEM that implements the standard hybrid construction, meaning {@link #encaps(EncryptionKey)}
 * generates a random key and encrypts it afterwards with some encryption
 * scheme.
 * <p>
 * Implementations of this abstract class need to define how to generate random
 * plaintexts for the encryption scheme and how to derive a secret key (for a
 * symmetric scheme) from the random plaintext (key derivation function).
 */

public abstract class AbstractHybridPredicateKEM extends AbstractHybridConstructionKEM
        implements PredicateKEM<SymmetricKey> {

    public AbstractHybridPredicateKEM(EncryptionScheme scheme, KeyDerivationFunction<? extends SymmetricKey> kdf) {
        super(scheme, kdf);
    }

    public AbstractHybridPredicateKEM(EncryptionScheme scheme) {
        super(scheme, new HashBasedKeyDerivationFunction());
    }
}
