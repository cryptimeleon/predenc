package org.cryptimeleon.predenc.abe.fuzzy.small;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;
import org.cryptimeleon.predenc.MasterSecret;

import java.util.Map;
import java.util.Objects;

/**
 * The {@link MasterSecret} for the {@link IBEFuzzySW05Small} generated
 * in the {@link IBEFuzzySW05SmallSetup}.
 */
public class IBEFuzzySW05SmallMasterSecret implements MasterSecret {

    @Represented(restorer = "zp")
    private ZpElement y;

    @Represented(restorer = "attr -> zp")
    private Map<Attribute, ZpElement> t;

    public IBEFuzzySW05SmallMasterSecret(ZpElement y, Map<Attribute, ZpElement> t2) {
        this.y = y;
        this.t = t2;
    }

    public IBEFuzzySW05SmallMasterSecret(Representation repr, IBEFuzzySW05SmallPublicParameters kpp) {
        Zp zp = new Zp(kpp.getGroupG1().size());
        new ReprUtil(this).register(zp, "zp").deserialize(repr);
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
        IBEFuzzySW05SmallMasterSecret other = (IBEFuzzySW05SmallMasterSecret) obj;
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
