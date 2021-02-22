package org.cryptimeleon.predenc.abe.distributed;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.predenc.MasterSecret;

/**
 * A share of a {@link MasterSecret}.
 * Distributed over servers.
 */
public interface MasterKeyShare extends Representable {

    public int getServerID();

}
