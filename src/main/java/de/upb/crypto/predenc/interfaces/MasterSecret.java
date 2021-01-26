package de.upb.crypto.predenc.interfaces;

import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.math.serialization.Representable;

/**
 * A key used to generate {@link DecryptionKey}s in a predicate encryption scheme.
 * This key will typically be created during setup of a scheme (for which there is no common interface).
 *
 * @author Jan
 */
public interface MasterSecret extends Representable {
}
