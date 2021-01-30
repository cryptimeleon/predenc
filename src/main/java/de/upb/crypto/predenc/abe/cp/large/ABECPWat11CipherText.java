package de.upb.crypto.predenc.abe.cp.large;

import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.predenc.kem.abe.cp.large.ABECPWat11KEMCipherText;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link CipherText} for {@link ABECPWat11}.
 */
public class ABECPWat11CipherText extends ABECPWat11KEMCipherText {

    @Represented(restorer = "GT")
    private GroupElement ePrime; // in G_T

    public ABECPWat11CipherText(Policy policy, GroupElement ePrime, GroupElement eTwoPrime,
                                Map<BigInteger, GroupElement> e) {
        super(policy, eTwoPrime, e);
        this.ePrime = ePrime;
    }

    public ABECPWat11CipherText(Representation repr, ABECPWat11PublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupGT(), "GT").register(pp.getGroupG1(), "G1")
                .deserialize(repr);
    }

    public GroupElement getEPrime() {
        return ePrime;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((ePrime == null) ? 0 : ePrime.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;
        ABECPWat11CipherText other = (ABECPWat11CipherText) obj;
        return super.equals(other)
                && Objects.equals(ePrime, other.ePrime);
    }

}
