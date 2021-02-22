package org.cryptimeleon.predenc.abe.fuzzy.large;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.*;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.*;

/**
 * An identity is a collection of {@link BigIntegerAttribute}
 */
public class Identity implements StandaloneRepresentable, KeyIndex, CiphertextIndex, UniqueByteRepresentable {
    @UniqueByteRepresented
    @Represented
    private Set<BigIntegerAttribute> attributes;

    public Identity(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    /**
     * Creates an empty identity
     */
    public Identity() {
        attributes = new HashSet<>();
    }

    /**
     * Creates an identity
     *
     * @param attributes initial attributes
     */
    public Identity(Collection<BigIntegerAttribute> attributes) {
        this.attributes = new HashSet<>();
        this.attributes.addAll(attributes);
    }

    /**
     * Creates an identity
     *
     * @param attributes initial attributes
     */
    public Identity(BigIntegerAttribute... attributes) {
        this.attributes = new HashSet<>();
        Collections.addAll(this.attributes, attributes);
    }

    /**
     * Adds a new attribute to this identity
     *
     * @param attribute new attribute
     */
    public void addAttribute(BigIntegerAttribute attribute) {
        attributes.add(attribute);
    }

    /**
     * Gets all attributes in this identity
     *
     * @return set of attributes
     */
    public Set<BigIntegerAttribute> getAttributes() {
        return attributes;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        Identity other = (Identity) obj;
        return Objects.equals(attributes, other.attributes);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public String toString() {
        Object[] array = attributes.toArray();
        Arrays.sort(array);
        return Arrays.toString(array);
    }

    @Override
    public int hashCode() {
        return attributes.hashCode();
    }

    public Identity intersect(Identity other) {
        Identity result = new Identity();
        for (BigIntegerAttribute i : attributes) {
            if (other.getAttributes().contains(i)) {
                result.addAttribute(i);
            }
        }
        return result;
    }

    /**
     * Creates a policy out of this identity
     *
     * @param threshold the amount of attributes in the intersection that the policy
     *                  needs to be fulfilled
     * @return the resulting {@link ThresholdPolicy}
     */
    public Policy toPolicy(int threshold) {
        return new ThresholdPolicy(threshold, attributes);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
