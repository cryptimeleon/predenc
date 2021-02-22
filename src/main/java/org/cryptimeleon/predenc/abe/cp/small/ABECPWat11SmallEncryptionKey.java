package org.cryptimeleon.predenc.abe.cp.small;

import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * An {@link EncryptionKey} for the {@link ABECPWat11Small} that stores a
 * {@link Policy} as {@link CiphertextIndex}.
 * <p>
 * This key should be created by
 * {@link ABECPWat11Small#generateEncryptionKey(CiphertextIndex)}
 */
public class ABECPWat11SmallEncryptionKey implements EncryptionKey {

    @UniqueByteRepresented
    @Represented
    private Policy policy;

    public ABECPWat11SmallEncryptionKey(Policy policy) {
        this.policy = policy;
    }

    public ABECPWat11SmallEncryptionKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Policy getPolicy() {
        return policy;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((policy == null) ? 0 : policy.hashCode());
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
        ABECPWat11SmallEncryptionKey other = (ABECPWat11SmallEncryptionKey) obj;
        return Objects.equals(policy, other.policy);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
