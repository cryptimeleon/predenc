package org.cryptimeleon.predenc.kem;

import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanism;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.predenc.MasterSecret;
import org.cryptimeleon.predenc.Predicate;

/**
 * Interface for implementing predicate encryption based KEMs.
 * <p>
 * The only difference between
 * the encryption scheme and the key encapsulation mechanism (KEM) is
 * that the KEM will not encrypt arbitrary user-defined messages
 * but will instead be able to generate random message-ciphertext
 * pairs (m, c). See {@link KeyEncapsulationMechanism} for details.
 *
 * @see KeyEncapsulationMechanism
 *
 * @param <T> type of the encapsulated key
 */
public interface PredicateKEM<T> extends KeyEncapsulationMechanism<T> {
    /**
     * Recreates a master secret key from its representation.
     */
    MasterSecret restoreMasterSecret(Representation repr);

    /**
     * Generates a decryption key that will be able to
     * decrypt ciphertexts where {@code getPredicate().check(kind, cind) == true}.
     *
     * @param msk the master secret obtained during setup
     * @param kind the key index specifying which ciphertexts are decryptable
     * @return the decryption key
     */
    DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind);

    /**
     * Generates an encryption key such that ciphertexts created using
     * that key are decryptable using keys where {@code getPredicate().check(kind, cind) == true}.
     *
     * @param cind the ciphertext index specifying who should be able to decrypt the ciphertext
     * @return the encryption key
     */
    EncryptionKey generateEncryptionKey(CiphertextIndex cind);

    /**
     * The predicate of this {@code PredicateEncryptionScheme}.
     *
     * @see Predicate
     */
    Predicate getPredicate();

    /**
     * Shorthand for {@code encaps(generateEncryptionKey(cind))}.
     */
    default KeyAndCiphertext<T> encaps(CiphertextIndex cind) {
        return encaps(generateEncryptionKey(cind));
    }

    /**
     * Checks whether a holder of a key from {@code kind} should be able to
     * decrypt ciphertexts encrypted using {@code cind}.
     */
    default boolean checkPredicate(KeyIndex kind, CiphertextIndex cind) {
        return getPredicate().check(kind, cind);
    }
}
