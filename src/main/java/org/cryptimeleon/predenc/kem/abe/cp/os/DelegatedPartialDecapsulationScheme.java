package org.cryptimeleon.predenc.kem.abe.cp.os;

import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.kem.KeyEncapsulationMechanism;
import org.cryptimeleon.math.serialization.Representation;

/**
 * @see DelegatedPartialDecryptionScheme
 */
public interface DelegatedPartialDecapsulationScheme<T> extends KeyEncapsulationMechanism<T> {
    public static class TransformationAndDecryptionKey {
        public TransformationKey transformationKey;
        public DecryptionKey decryptionKey;
    }

    /**
     * Transforms a ciphertext of this scheme to a ciphertext of
     * another scheme.
     *
     * @param original     the original ciphertext
     * @param transformKey key to use for transformation
     * @return a transformed ciphertext for the scheme returned by {@link #getSchemeForTransformedCiphertexts()}
     */
    public CipherText transform(CipherText original, TransformationKey transformKey);

    /**
     * Takes a decryption key of this encryption scheme and
     * generates a transformation key to use with this scheme,
     * and a decryption key that can be used to decrypt ciphertexts
     * that are the result of transformation with the transformation key.
     *
     * @param original the original decryption key
     * @return a transformation key and a decryption key for the scheme returned by
     *         {@link #getSchemeForTransformedCiphertexts()}
     */
    public TransformationAndDecryptionKey generateTransformationKey(DecryptionKey original);

    /**
     * Returns the scheme that the transformed ciphertexts are meaningful to.
     */
    public KeyEncapsulationMechanism<T> getSchemeForTransformedCiphertexts();

    /**
     * Recreates a transformation key from representation.
     */
    public TransformationKey restoreTransformationKey(Representation repr);
}
