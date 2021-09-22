package org.cryptimeleon.predenc.abe.cp.small.asymmetric;

import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Objects;

public class ABECPWat11AsymSmallEncryptionKey implements EncryptionKey {

    @Represented
    private Policy policy;

    public ABECPWat11AsymSmallEncryptionKey(Policy policy) {
        this.policy = policy;
    }

    public ABECPWat11AsymSmallEncryptionKey(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Policy getPolicy() {
        return policy;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        return AnnotatedUbrUtil.autoAccumulate(byteAccumulator, this);
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
        ABECPWat11AsymSmallEncryptionKey other = (ABECPWat11AsymSmallEncryptionKey) obj;
        return Objects.equals(other.policy, policy);
    }
}
