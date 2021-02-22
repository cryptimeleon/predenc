package org.cryptimeleon.predenc.abe.kp.large;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;
import org.cryptimeleon.predenc.MasterSecret;

import java.util.Objects;

/**
 * The master secret for the {@link ABEKPGPSW06} generated on the
 * {@link ABEKPGPSW06Setup}.
 */
public class ABEKPGPSW06MasterSecret implements MasterSecret {

    // Uniformly random element in Z_{size(GroupG1)}
    @Represented(restorer = "Zp")
    private ZpElement y;

    public ABEKPGPSW06MasterSecret(ZpElement y) {
        this.y = y;
    }

    public ABEKPGPSW06MasterSecret(Representation repr, ABEKPGPSW06PublicParameters kpp) {
        Zp zp = new Zp(kpp.getGroupG1().size());
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((y == null) ? 0 : y.hashCode());
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
        ABEKPGPSW06MasterSecret other = (ABEKPGPSW06MasterSecret) obj;
        return Objects.equals(y, other.y);
    }

    public ZpElement getY() {
        return y;
    }
}