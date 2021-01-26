package de.upb.crypto.predenc;

import de.upb.crypto.predenc.common.interfaces.pe.CiphertextIndex;

/**
 * Defines who gets to decrypt which ciphertexts.
 *
 * @see PredicateEncryptionScheme#getPredicate()
 *
 * @author Jan
 */
public interface Predicate {
    /**
     * Checks whether a holder of a decryption key with associated {@code KexIndex} {@code kind} should be able to
     * decrypt ciphertexts encrypted using {@code CiphertextIndex} {@code cind}.
     *
     * @return true if the decryption is possible, else false
     */
    boolean check(KeyIndex kind, CiphertextIndex cind);
}
