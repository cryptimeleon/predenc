package de.upb.crypto.predenc.abe.fuzzy.large;

import de.upb.crypto.craco.common.attributes.BigIntegerAttribute;
import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.common.policies.ThresholdPolicy;
import de.upb.crypto.craco.common.predicate.CiphertextIndex;
import de.upb.crypto.craco.common.predicate.KeyIndex;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.*;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

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
