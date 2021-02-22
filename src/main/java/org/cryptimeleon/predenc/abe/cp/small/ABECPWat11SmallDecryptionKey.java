package org.cryptimeleon.predenc.abe.cp.small;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.predenc.MasterSecret;

import java.util.Map;
import java.util.Objects;

/**
 * A {@link DecryptionKey} for the {@link ABECPWat11Small} that stores a
 * {@link SetOfAttributes} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABECPWat11Small#generateDecryptionKey(MasterSecret, KeyIndex)}
 */
public class ABECPWat11SmallDecryptionKey implements DecryptionKey {

    @Represented(restorer = "G1")
    private GroupElement k, l;

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> mapK;

    public ABECPWat11SmallDecryptionKey(Representation repr, ABECPWat11SmallPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    public ABECPWat11SmallDecryptionKey(Map<Attribute, GroupElement> mapK, GroupElement k, GroupElement l) {
        this.mapK = mapK;
        this.k = k;
        this.l = l;
    }

    public GroupElement getK() {
        return k;
    }

    public GroupElement getL() {
        return l;
    }

    public Map<Attribute, GroupElement> getMapK() {
        return mapK;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mapK == null) ? 0 : mapK.hashCode());
        result = prime * result + ((k == null) ? 0 : k.hashCode());
        result = prime * result + ((l == null) ? 0 : l.hashCode());
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
        ABECPWat11SmallDecryptionKey other = (ABECPWat11SmallDecryptionKey) obj;
        return Objects.equals(mapK, other.mapK)
                && Objects.equals(k, other.k)
                && Objects.equals(l, other.l);
    }
}
