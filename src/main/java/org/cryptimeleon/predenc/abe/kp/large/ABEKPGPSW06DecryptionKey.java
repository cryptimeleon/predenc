package org.cryptimeleon.predenc.abe.kp.large;

import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.predenc.MasterSecret;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link DecryptionKey} for the {@link ABEKPGPSW06} that stores a {@link Policy} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABEKPGPSW06#generateDecryptionKey(MasterSecret, KeyIndex)}
 */
public class ABEKPGPSW06DecryptionKey implements DecryptionKey {
    @Represented
    private Policy policy;

    @Represented(restorer = "int -> G1")
    private Map<BigInteger, GroupElement> dElementMap;

    @Represented(restorer = "int -> G1")
    private Map<BigInteger, GroupElement> rElementMap;

    public ABEKPGPSW06DecryptionKey(Policy policy, Map<BigInteger, GroupElement> dElementMap,
                                    Map<BigInteger, GroupElement> rElementMap) {
        this.policy = policy;
        this.dElementMap = dElementMap;
        this.rElementMap = rElementMap;
    }

    public ABEKPGPSW06DecryptionKey(Representation repr, ABEKPGPSW06PublicParameters kpp) {
        new ReprUtil(this).register(kpp.getGroupG1(), "G1").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Policy getPolicy() {
        return policy;
    }

    public Map<BigInteger, GroupElement> getDElementMap() {
        return dElementMap;
    }

    public Map<BigInteger, GroupElement> getRElementMap() {
        return rElementMap;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((dElementMap == null) ? 0 : dElementMap.hashCode());
        result = prime * result + ((rElementMap == null) ? 0 : rElementMap.hashCode());
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
        ABEKPGPSW06DecryptionKey other = (ABEKPGPSW06DecryptionKey) obj;
        return Objects.equals(dElementMap, other.dElementMap)
                && Objects.equals(rElementMap, other.rElementMap)
                && Objects.equals(policy, other.policy);
    }

}
