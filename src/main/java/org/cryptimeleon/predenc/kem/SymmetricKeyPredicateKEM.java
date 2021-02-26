package org.cryptimeleon.predenc.kem;


import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.SymmetricKey;
import org.cryptimeleon.craco.kem.KeyDerivationFunction;
import org.cryptimeleon.craco.kem.KeyMaterial;
import org.cryptimeleon.craco.kem.SymmetricKeyKEM;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.predenc.MasterSecret;
import org.cryptimeleon.predenc.Predicate;

/**
 * A KEM that is implemented by the composition of a {@link PredicateKEM} providing {@link KeyMaterial} and a
 * {@link KeyDerivationFunction} that derives a {@link SymmetricKey} from the {@link KeyMaterial} produced by the KEM.
 * <p>
 * This should be used in combination with an symmetric encryption scheme to implement the standard hybrid encryption
 * technique.
 */
public class SymmetricKeyPredicateKEM extends SymmetricKeyKEM implements PredicateKEM<SymmetricKey> {

    public SymmetricKeyPredicateKEM(PredicateKEM<? extends KeyMaterial> kem,
                                    KeyDerivationFunction<? extends SymmetricKey> kdf) {
        super(kem, kdf);
    }

    public SymmetricKeyPredicateKEM(Representation repr) {
        super(repr);
    }

    @Override
    public MasterSecret restoreMasterSecret(Representation repr) {
        return ((PredicateKEM<? extends KeyMaterial>) kem).restoreMasterSecret(repr);
    }

    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        return ((PredicateKEM<? extends KeyMaterial>) kem).generateDecryptionKey(msk, kind);
    }

    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        return ((PredicateKEM<? extends KeyMaterial>) kem).generateEncryptionKey(cind);
    }

    @Override
    public Predicate getPredicate() {
        return ((PredicateKEM<? extends KeyMaterial>) kem).getPredicate();
    }
}
