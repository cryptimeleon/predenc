package org.cryptimeleon.predenc.kem.abe.kp.large;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.kem.KeyMaterial;
import org.cryptimeleon.craco.kem.UniqueByteKeyMaterial;
import org.cryptimeleon.craco.kem.UnqualifiedKeyException;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.predenc.abe.kp.large.*;
import org.cryptimeleon.predenc.kem.PredicateKEM;
import org.cryptimeleon.predenc.kem.SymmetricKeyPredicateKEM;

import java.util.Map;

/**
 * A KEM based on the KP-ABE large universe construction ({@link ABEKPGPSW06}.
 * <p>
 * For the basic idea of the construction consider a {@link ABEKPGPSW06CipherText} (\omega', E', E'', (E_i)_{i}) of
 * {@link ABEKPGPSW06}, where E' = m * Y^s for some message m, random number s and Y defined in the
 * scheme's setup {@link ABEKPGPSW06Setup}. The KEM now outputs E' dropping factor m as a key, i.e. Y^s, and
 * (\omega', E'',
 * (E_i)_{i}) as its encapsulation ({@link ABEKPGPSW06KEMCipherText}). The decryption of {@link ABEKPGPSW06}
 * just recovers Y^s from (\omega', E'', (E_i)_{i}) and computes E' / Y^s to obtain m. In the same way we can use this
 * to decapsulate the key Y^s.
 * <p>
 * This scheme only supplies {@link KeyMaterial}. It needs to be used in combination with a KDF to obtain a symmetric
 * key. For this, see {@link SymmetricKeyPredicateKEM}.
 */
public class ABEKPGPSW06KEM extends AbstractABEKPGPSW06 implements PredicateKEM<KeyMaterial> {
    public ABEKPGPSW06KEM(ABEKPGPSW06PublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public ABEKPGPSW06KEM(Representation repr) {
        this.pp = new ABEKPGPSW06PublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public KeyAndCiphertext<KeyMaterial> encaps(EncryptionKey publicKey) {
        if (!(publicKey instanceof ABEKPGPSW06EncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this encryption scheme.");
        ABEKPGPSW06EncryptionKey pk = (ABEKPGPSW06EncryptionKey) publicKey;

        // Check the size validity of the attribute set
        SetOfAttributes attributes = pk.getAttributes();
        if (attributes.size() > pp.getN().intValue()) {
            throw new IllegalArgumentException(
                    "maximum attribute size is " + pp.getN() + ", but |omega| is " + attributes.size());
        }

        // s <- Z_p
        Zp.ZpElement s = zp.getUniformlyRandomUnit();
        // E'' = g^s \in G1
        GroupElement eTwoPrime = pp.getG1Generator().pow(s).compute();
        // E_i = T(i)^s i \in omega
        Map<Attribute, GroupElement> eElementMap = restoreE(attributes, s);

        KeyAndCiphertext<KeyMaterial> output = new KeyAndCiphertext<>();
        output.key = new UniqueByteKeyMaterial(pp.getY().pow(s).compute(), pp.getGroupGT().size().intValue());
        output.encapsulatedKey = new ABEKPGPSW06KEMCipherText(attributes, eTwoPrime, eElementMap);

        return output;
    }

    @Override
    public KeyMaterial decaps(CipherText encapsulatedKey, DecryptionKey privateKey) throws UnqualifiedKeyException {
        if (!(encapsulatedKey instanceof ABEKPGPSW06KEMCipherText))
            throw new IllegalArgumentException("Not a valid cipher text for this scheme");
        if (!(privateKey instanceof ABEKPGPSW06DecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme");

        ABEKPGPSW06KEMCipherText ct = (ABEKPGPSW06KEMCipherText) encapsulatedKey;
        ABEKPGPSW06DecryptionKey sk = (ABEKPGPSW06DecryptionKey) privateKey;

        // restore Z = Y^{-s}
        GroupElement yToTheS = restoreYs(sk, ct);

        return new UniqueByteKeyMaterial(yToTheS, pp.getGroupGT().size().intValue());
    }

    @Override
    public CipherText getEncapsulatedKey(Representation repr) {
        return new ABEKPGPSW06KEMCipherText(repr, pp);
    }

    @Override
    public EncryptionKey getEncapsulationKey(Representation repr) {
        return new ABEKPGPSW06EncryptionKey(repr);
    }

    @Override
    public DecryptionKey getDecapsulationKey(Representation repr) {
        return new ABEKPGPSW06DecryptionKey(repr, pp);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        return super.equals(obj);
    }
}
