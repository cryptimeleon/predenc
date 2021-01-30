package de.upb.crypto.predenc.kem.abe.cp.os;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used to transform a ciphertext to another ciphertext,
 * possibly belonging to another scheme and possibly hiding a different
 * plaintext.
 */
public interface TransformationKey extends Representable {

}
