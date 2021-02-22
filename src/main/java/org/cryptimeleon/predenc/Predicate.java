package org.cryptimeleon.predenc;

import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.predenc.abe.PredicateEncryptionScheme;

/**
 * Defines who gets to decrypt which ciphertexts.
 *
 * @see PredicateEncryptionScheme#getPredicate()
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
