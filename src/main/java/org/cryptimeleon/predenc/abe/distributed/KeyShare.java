package org.cryptimeleon.predenc.abe.distributed;

import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.math.serialization.Representable;

/**
 * Share of a decryption key.
 * Can be used to recreate the key if enough are available.
 */
public interface KeyShare extends Representable {

    public int getServerID();

    public KeyIndex getKeyIndex();
}
