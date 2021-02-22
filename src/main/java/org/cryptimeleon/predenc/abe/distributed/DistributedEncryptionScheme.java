package org.cryptimeleon.predenc.abe.distributed;

import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionScheme;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.predenc.MasterSecret;

import java.util.List;

/**
 * Interface for distributed encryption schemes.
 * <p>
 * The idea is that the {@link MasterSecret} is divided into L
 * {@link MasterKeyShare}. These Shares are distributed over L servers.
 * <p>
 * A KeyShare is generated out of a MasterKeyShare.
 * <p>
 * T out of L KeyShares are needed in order to successfully recreate a
 * DecryptionKey that can be used in an Encryption Scheme.
 */
public interface DistributedEncryptionScheme extends EncryptionScheme {

    int getServerCount();

    int getMinAmountToRecreate();

    boolean shareVerify(KeyShare keyShare);

    /**
     * Combines a list of {@link KeyShare} to a {@link DecryptionKey}. The scheme needs a
     * specific amount of {@link KeyShare} in order to successfully create a
     * {@link DecryptionKey}.
     *
     * @param keyShares the key shares to use to construct the decryption key
     * @return the resulting decryption key
     */
    DecryptionKey combineKeyShares(List<KeyShare> keyShares);

    KeyShare generateKeyShare(MasterKeyShare masterKeyShare, KeyIndex keyData);

    KeyShare getKeyShare(Representation repr);

    MasterKeyShare getMasterKeyShare(Representation repr);

}
