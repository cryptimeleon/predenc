package de.upb.crypto.predenc.abe.ibe;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * A {@link DecryptionKey} for the {@link FullIdent}.
 * <p>
 * This key is generated by
 * {@link FullIdent#generateDecryptionKey(MasterSecret, KeyIndex)}.
 *
 * @author Mirko Jürgens
 */
public class FullIdentDecryptionKey implements DecryptionKey {

    @Represented(restorer = "G1")
    private GroupElement d_id; //s * Q_id

    public FullIdentDecryptionKey(GroupElement d_id) {
        this.d_id = d_id;
    }

    public FullIdentDecryptionKey(Representation repr, FullIdentPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getD_id() {
        return d_id;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((d_id == null) ? 0 : d_id.hashCode());
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
        FullIdentDecryptionKey other = (FullIdentDecryptionKey) obj;
        return Objects.equals(d_id, other.d_id);
    }
}
