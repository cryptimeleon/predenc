package de.upb.crypto.predenc.abe.fuzzy.large;

import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * An {@link EncryptionKey} for the {@link IBEFuzzySW05}. The Key
 * is generated by
 * {@link IBEFuzzySW05#generateEncryptionKey(CiphertextIndex)}
 *
 * @author Mirko Jürgens
 */
public class IBEFuzzySW05EncryptionKey implements EncryptionKey {

    @UniqueByteRepresented
    @Represented
    private Identity identity;

    public IBEFuzzySW05EncryptionKey(Identity id) {
        this.identity = id;
    }

    public IBEFuzzySW05EncryptionKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    /**
     * Getter for {@link #identity}
     *
     * @return the encryption's key identity
     */
    public Identity getIdentity() {
        return identity;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((identity == null) ? 0 : identity.hashCode());
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
        IBEFuzzySW05EncryptionKey other = (IBEFuzzySW05EncryptionKey) obj;
        return Objects.equals(identity, other.identity);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

}
