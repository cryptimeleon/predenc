package org.cryptimeleon.predenc;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.impl.ByteArrayAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.HashIntoGroup;
import org.cryptimeleon.math.structures.rings.polynomial.LagrangeUtils;
import org.cryptimeleon.math.structures.rings.zn.HashIntoZn;

import java.math.BigInteger;
import java.util.*;

/**
 * Implements the hash function from appendix B of [Wat08].
 * <p>
 * [Wat08] Waters, Brent.
 * "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization."
 * Public Key Cryptography – PKC 2011. Springer Berlin Heidelberg,
 */
public class WatersHash implements HashIntoGroup {
    @Represented
    private Group g;
    @Represented(restorer = "[g]")
    protected List<GroupElement> T;

    public WatersHash(Group g, int n) {
        T = new ArrayList<>();
        this.g = g;
        for (int i = 1; i <= n; i++) {
            T.add(g.getUniformlyRandomNonNeutral().compute());
        }
    }

    public WatersHash(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public GroupElement hash(byte[] x) {
        HashIntoZn baseHash = new HashIntoZn(g.size());
        Map<BigInteger, GroupElement> knownPoints = new HashMap<>();
        for (int i = 1; i <= T.size(); ++i) {
            knownPoints.put(BigInteger.valueOf(i), T.get(i-1));
        }
        return LagrangeUtils.interpolateInTheExponent(knownPoints, baseHash.hash(x).asInteger());
    }

    public List<GroupElement> getT() {
        return T;
    }

    public Group getG() {
        return g;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(T);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        WatersHash other = (WatersHash) obj;
        return Objects.equals(T, other.T);
    }

    @Override
    public GroupElement hash(UniqueByteRepresentable ubr) {
        ByteAccumulator acc = new ByteArrayAccumulator();
        acc = ubr.updateAccumulator(acc);
        return hash(acc.extractBytes());
    }
}
