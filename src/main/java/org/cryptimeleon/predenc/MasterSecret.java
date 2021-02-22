package org.cryptimeleon.predenc;

import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.math.serialization.Representable;

/**
 * A key used to generate {@link DecryptionKey}s in a predicate encryption scheme.
 * This key will typically be created during setup of a scheme (for which there is no common interface).
 */
public interface MasterSecret extends Representable {
}
