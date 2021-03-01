package org.cryptimeleon.predenc.kem.abe.cp.small;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.predenc.MasterSecret;
import org.cryptimeleon.predenc.Predicate;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11Small;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11SmallPublicParameters;
import org.cryptimeleon.predenc.kem.AbstractHybridPredicateKEM;
import org.cryptimeleon.math.serialization.Representation;

import java.util.Objects;

/**
 * A KEM that produces AES keys encapsulated via ABE
 */
public class ABECPWat11SmallKEM extends AbstractHybridPredicateKEM {

    private ABECPWat11Small scheme;

    public ABECPWat11SmallKEM(ABECPWat11Small scheme) {
        super(scheme, new HashBasedKeyDerivationFunction());
        this.scheme = scheme;
    }

    public ABECPWat11SmallKEM(Representation repr) {
        this(new ABECPWat11Small(repr));
    }

    @Override
    protected PlainText generateRandomPlaintext() {
        return new GroupElementPlainText(scheme.getPublicParameters().getGroupGT().getUniformlyRandomElement());
    }

    @Override
    public Representation getRepresentation() {
        return scheme.getRepresentation();
    }

    public ByteArrayImplementation getKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    protected int getPlaintextMinEntropyInBit() {
        return scheme.getPublicParameters().getGroupGT().size().bitLength();
    }

    @Override
    public MasterSecret restoreMasterSecret(Representation repr) {
        return scheme.restoreMasterSecret(repr);
    }

    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        return scheme.generateDecryptionKey(msk, kind);
    }

    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        return scheme.generateEncryptionKey(cind);
    }

    @Override
    public Predicate getPredicate() {
        return scheme.getPredicate();
    }

    public ABECPWat11SmallPublicParameters getPublicParameters() {
        return scheme.getPublicParameters();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((scheme == null) ? 0 : scheme.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABECPWat11SmallKEM other = (ABECPWat11SmallKEM) obj;
        return Objects.equals(scheme, other.scheme);
    }

}
