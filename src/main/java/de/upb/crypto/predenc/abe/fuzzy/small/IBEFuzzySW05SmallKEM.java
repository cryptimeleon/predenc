package de.upb.crypto.predenc.abe.fuzzy.small;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.kem.AbstractHybridPredicateKEM;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

/**
 * A KEM that produces AES keys encapsulated via ABE
 *
 * @author Jan
 */
public class IBEFuzzySW05SmallKEM extends AbstractHybridPredicateKEM {

    private IBEFuzzySW05Small scheme;

    public IBEFuzzySW05SmallKEM(IBEFuzzySW05Small scheme) {
        super(scheme, new HashBasedKeyDerivationFunction());
        this.scheme = scheme;
    }

    public IBEFuzzySW05SmallKEM(Representation repr) {
        this(new IBEFuzzySW05Small(repr));
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
    public MasterSecret getMasterSecret(Representation repr) {
        return scheme.getMasterSecret(repr);
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

    public IBEFuzzySW05SmallPublicParameters getPublicParameters() {
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
        IBEFuzzySW05SmallKEM other = (IBEFuzzySW05SmallKEM) obj;
        return Objects.equals(scheme, other.scheme);
    }

}