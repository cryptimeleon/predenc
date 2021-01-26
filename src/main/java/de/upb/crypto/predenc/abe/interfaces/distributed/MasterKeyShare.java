package de.upb.crypto.predenc.abe.interfaces.distributed;

import de.upb.crypto.predenc.common.interfaces.pe.MasterSecret;
import de.upb.crypto.math.serialization.Representable;

/**
 * A share of a {@link MasterSecret}.
 * Distributed over servers.
 */
public interface MasterKeyShare extends Representable {

    public int getServerID();

}
