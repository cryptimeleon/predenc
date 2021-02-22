package org.cryptimeleon.predenc.kem.abe.cp.os;

import org.cryptimeleon.math.serialization.Representable;

/**
 * A key that is used to transform a ciphertext to another ciphertext,
 * possibly belonging to another scheme and possibly hiding a different
 * plaintext.
 */
public interface TransformationKey extends Representable {

}
