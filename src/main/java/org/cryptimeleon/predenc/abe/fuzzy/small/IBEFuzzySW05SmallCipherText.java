package org.cryptimeleon.predenc.abe.fuzzy.small;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Map;
import java.util.Objects;

/**
 * The {@link CipherText} for the {@link IBEFuzzySW05Small}
 */
public class IBEFuzzySW05SmallCipherText implements CipherText {

    @Represented
    private SetOfAttributes omega_prime;

    // in G_T
    @Represented(restorer = "GT")
    private GroupElement e_prime;

    // in G_1
    @Represented(restorer = "attr -> G1")
    private Map<Attribute, GroupElement> e;

    public IBEFuzzySW05SmallCipherText(SetOfAttributes identity, GroupElement E_prime,
                                       Map<Attribute, GroupElement> e2) {
        this.omega_prime = identity;
        this.e_prime = E_prime;
        this.e = e2;
    }

    public IBEFuzzySW05SmallCipherText(Representation repr, IBEFuzzySW05SmallPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").register(pp.getGroupGT(), "GT")
                .deserialize(repr);
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public SetOfAttributes getOmega_prime() {
        return omega_prime;
    }

    public GroupElement getE_prime() {
        return e_prime;
    }

    public Map<Attribute, GroupElement> getE() {
        return e;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((e_prime == null) ? 0 : e_prime.hashCode());
        result = prime * result + ((omega_prime == null) ? 0 : omega_prime.hashCode());
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
        IBEFuzzySW05SmallCipherText other = (IBEFuzzySW05SmallCipherText) obj;
        return Objects.equals(e, other.e)
                && Objects.equals(e_prime, other.e_prime)
                && Objects.equals(omega_prime, other.omega_prime);
    }
}
