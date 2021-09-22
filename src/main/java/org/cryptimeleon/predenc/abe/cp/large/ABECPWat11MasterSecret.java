package org.cryptimeleon.predenc.abe.cp.large;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.predenc.MasterSecret;

import java.util.Objects;

/**
 * The MasterSecret for the {@link ABECPWat11} generated in the
 * {@link ABECPWat11Setup}
 */
public class ABECPWat11MasterSecret implements MasterSecret {

    @Represented(restorer = "G1")
    private GroupElement g_y; // in G_1

    public ABECPWat11MasterSecret(GroupElement g_y) {
        this.g_y = g_y;
    }

    public ABECPWat11MasterSecret(Group groupG1, Representation repr) {
        new ReprUtil(this).register(groupG1, "G1").deserialize(repr);
    }

    public GroupElement get() {
        return g_y;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((g_y == null) ? 0 : g_y.hashCode());
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
        ABECPWat11MasterSecret other = (ABECPWat11MasterSecret) obj;
        return Objects.equals(g_y, other.g_y);
    }
}
