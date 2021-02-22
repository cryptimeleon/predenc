package org.cryptimeleon.predenc.abe.cp.large.distributed;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.predenc.abe.distributed.KeyShare;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Map;
import java.util.Objects;

public class DistributedABECPWat11KeyShare implements KeyShare {

    @Represented(restorer = "G1")
    private GroupElement d_prime;

    @Represented(restorer = "G1")
    private GroupElement d_two_prime;

    @Represented
    private Integer serverID;

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> d_xi;

    @Represented
    private SetOfAttributes omega;

    public DistributedABECPWat11KeyShare(GroupElement d_prime, GroupElement d_two_prime, int serverID,
                                         Map<Attribute, GroupElement> d_xi, SetOfAttributes omega) {
        this.d_prime = d_prime;
        this.d_two_prime = d_two_prime;
        this.serverID = serverID;
        this.d_xi = d_xi;
        this.omega = omega;
    }

    public DistributedABECPWat11KeyShare(Representation repr, DistributedABECPWat11PublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getD_prime() {
        return d_prime;
    }

    public GroupElement getD_two_prime() {
        return d_two_prime;
    }

    @Override
    public int getServerID() {
        return serverID;
    }

    public Map<Attribute, GroupElement> getD_xi() {
        return d_xi;
    }

    @Override
    public SetOfAttributes getKeyIndex() {
        return omega;
    }

    @Override
    public int hashCode() {
        return Objects.hash(d_prime, d_two_prime, d_xi, omega, serverID);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        DistributedABECPWat11KeyShare other = (DistributedABECPWat11KeyShare) obj;
        return Objects.equals(d_prime, other.d_prime)
                && Objects.equals(d_two_prime, other.d_two_prime)
                && Objects.equals(d_xi, other.d_xi)
                && Objects.equals(omega, other.omega)
                && Objects.equals(serverID, other.serverID);
    }
}
