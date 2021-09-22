package org.cryptimeleon.predenc.abe.cp.small.asymmetric;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.predenc.MasterSecret;

import java.util.Objects;

public class ABECPWat11AsymSmallMasterSecret implements MasterSecret {

    @Represented(restorer = "G1")
    private GroupElement gAlpha; // in G_1

    public ABECPWat11AsymSmallMasterSecret(GroupElement gAlpha) {
        this.gAlpha = gAlpha;
    }

    public ABECPWat11AsymSmallMasterSecret(Representation repr, Group groupG1) {
        new ReprUtil(this).register(groupG1, "G1").deserialize(repr);
    }

    public GroupElement get() {
        return gAlpha;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }


    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((gAlpha == null) ? 0 : gAlpha.hashCode());
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
        ABECPWat11AsymSmallMasterSecret other = (ABECPWat11AsymSmallMasterSecret) obj;
        return Objects.equals(gAlpha, other.gAlpha);
    }
}
