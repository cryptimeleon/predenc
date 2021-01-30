package de.upb.crypto.predenc.abe.fuzzy.large;

import de.upb.crypto.predenc.kem.fuzzy.large.IBEFuzzySW05KEMCipherText;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * Ciphertext for {@link IBEFuzzySW05}.
 * <p>
 * It extends {@link IBEFuzzySW05KEMCipherText} by the component {@link #ePrime}.
 */
public class IBEIBEFuzzySW05SW05CipherText extends IBEFuzzySW05KEMCipherText {

    /**
     * E' \in G_1
     */
    @Represented(restorer = "GT")
    private GroupElement ePrime;

    public IBEIBEFuzzySW05SW05CipherText(Identity omegaPrime, GroupElement ePrime, GroupElement eTwoPrime,
                                         Map<BigInteger, GroupElement> e) {
        super(omegaPrime, eTwoPrime, e);
        this.ePrime = ePrime;
    }

    public IBEIBEFuzzySW05SW05CipherText(Representation repr, IBEFuzzySW05PublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").register(pp.getGroupGT(), "GT")
                .deserialize(repr);
    }

    public GroupElement getEPrime() {
        return ePrime;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((ePrime == null) ? 0 : ePrime.hashCode());
        return result;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass()) 
            return false;
        IBEIBEFuzzySW05SW05CipherText other = (IBEIBEFuzzySW05SW05CipherText) o;
        return super.equals(other) && Objects.equals(ePrime, other.ePrime);
    }
}
