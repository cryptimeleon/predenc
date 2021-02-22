package org.cryptimeleon.predenc.abe.ibe;

import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Arrays;
import java.util.Objects;

/**
 * The {@link CiphertextIndex} for {@link FullIdent}.
 */
public class FullIdentCipherText implements CipherText {

    @Represented(restorer = "G1")
    private GroupElement u; // P^r \in G1

    @Represented
    private byte[] v; // sigma \oplus H_2(g_id^r)

    @Represented
    private byte[] w; // M \oplus H_4(sigma)

    public FullIdentCipherText(GroupElement U, byte[] V, byte[] W) {
        this.u = U;
        this.v = V;
        this.w = W;
    }

    public FullIdentCipherText(Representation repr, FullIdentPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getU() {
        return u;
    }

    public byte[] getV() {
        return v;
    }

    public byte[] getW() {
        return w;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((u == null) ? 0 : u.hashCode());
        result = prime * result + Arrays.hashCode(v);
        result = prime * result + Arrays.hashCode(w);
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
        FullIdentCipherText other = (FullIdentCipherText) obj;
        return Objects.equals(u, other.u)
                && Arrays.equals(v, other.v)
                && Arrays.equals(w, other.w);
    }
}
