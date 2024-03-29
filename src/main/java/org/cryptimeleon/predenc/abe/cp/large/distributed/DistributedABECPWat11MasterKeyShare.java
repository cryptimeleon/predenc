package org.cryptimeleon.predenc.abe.cp.large.distributed;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.predenc.abe.distributed.MasterKeyShare;

import java.math.BigInteger;
import java.util.Objects;

public class DistributedABECPWat11MasterKeyShare implements StandaloneRepresentable, MasterKeyShare {

    @Represented
    private Integer serverID;

    @Represented
    private BigInteger share;

    public DistributedABECPWat11MasterKeyShare(int serverID, BigInteger share) {
        super();
        this.serverID = serverID;
        this.share = share;
    }

    public DistributedABECPWat11MasterKeyShare(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public int getServerID() {
        return serverID;
    }

    public BigInteger getShare() {
        return share;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + serverID;
        result = prime * result + ((share == null) ? 0 : share.hashCode());
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
        DistributedABECPWat11MasterKeyShare other = (DistributedABECPWat11MasterKeyShare) obj;
        return Objects.equals(serverID, other.serverID)
                && Objects.equals(share, other.share);
    }

}
