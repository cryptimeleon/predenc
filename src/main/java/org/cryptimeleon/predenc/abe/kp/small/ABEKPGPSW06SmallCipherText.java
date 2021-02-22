package org.cryptimeleon.predenc.abe.kp.small;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Map;
import java.util.Objects;

/**
 * A {@link CipherText} for the {@link ABEKPGPSW06Small}.
 */
public class ABEKPGPSW06SmallCipherText implements CipherText {

    //E_prime := m * Y^s \in G_T
    @Represented(restorer = "GT")
    private GroupElement E_prime;
    //E_i := T_i^s , i \in attributes, T_i \in G1
    @Represented(restorer = "attr -> G1")
    private Map<Attribute, GroupElement> E;

    public ABEKPGPSW06SmallCipherText(GroupElement E_prime, Map<Attribute, GroupElement> E) {
        this.E_prime = E_prime;
        this.E = E;
    }

    public ABEKPGPSW06SmallCipherText(Representation repr, ABEKPGPSW06SmallPublicParameters kpp) {
        new ReprUtil(this).register(kpp.getGroupGT(), "GT").register(kpp.getGroupG1(), "G1")
                .deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getE_prime() {
        return E_prime;
    }

    public Map<Attribute, GroupElement> getE() {
        return E;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((E == null) ? 0 : E.hashCode());
        result = prime * result + ((E_prime == null) ? 0 : E_prime.hashCode());
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
        ABEKPGPSW06SmallCipherText other = (ABEKPGPSW06SmallCipherText) obj;
        return Objects.equals(E, other.E)
                && Objects.equals(E_prime, other.E_prime);
    }

}
