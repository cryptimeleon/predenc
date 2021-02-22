package org.cryptimeleon.predenc.abe.kp.small;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.predenc.MasterSecret;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Map;
import java.util.Objects;

/**
 * The master secret for the {@link ABEKPGPSW06Small} generated in the
 * {@link ABEKPGPSW06SmallSetup}.
 */
public class ABEKPGPSW06SmallMasterSecret implements MasterSecret {

    @Represented(restorer = "Zp")
    private ZpElement y;

    @Represented(restorer = "attr -> Zp")
    private Map<Attribute, ZpElement> t;

    public ABEKPGPSW06SmallMasterSecret(ZpElement y, Map<Attribute, ZpElement> t) {
        this.y = y;
        this.t = t;
    }

    public ABEKPGPSW06SmallMasterSecret(Representation repr, ABEKPGPSW06SmallPublicParameters kpp) {
        new ReprUtil(this).register(new Zp(kpp.getGroupG1().size()), "Zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABEKPGPSW06SmallMasterSecret other = (ABEKPGPSW06SmallMasterSecret) obj;
        return Objects.equals(t, other.t)
                && Objects.equals(y, other.y);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((t == null) ? 0 : t.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        return result;
    }

    public ZpElement getY() {
        return y;
    }

    public Map<Attribute, ZpElement> getT() {
        return t;
    }

}
