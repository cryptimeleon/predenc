package de.upb.crypto.predenc.abe.distributed;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.predenc.MasterSecret;

/**
 * A share of a {@link MasterSecret}.
 * Distributed over servers.
 */
public interface MasterKeyShare extends Representable {

    public int getServerID();

}
