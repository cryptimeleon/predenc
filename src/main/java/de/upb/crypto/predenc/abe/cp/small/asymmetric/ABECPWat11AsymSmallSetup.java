package de.upb.crypto.predenc.abe.cp.small.asymmetric;

import de.upb.crypto.predenc.abe.interfaces.Attribute;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ABECPWat11AsymSmallSetup {

    private ABECPWat11AsymSmallPublicParameters pp;
    private ABECPWat11AsymSmallMasterSecret msk;

    /**
     * Generate public parameters and the master secret.
     * <p>
     * Sets up public parameters and the master secret for a given security
     * parameter securityParameter. The universe specifies which attributes can
     * be used in the {@link ABECPWat11AsymSmallEncryptionKey} and in the {@link ABECPWat11AsymSmallDecryptionKey}.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param universe          the universe of attributes
     * @param debug             - enable debugging.
     */
    public void doKeyGen(int securityParameter, Collection<? extends Attribute> universe, boolean debug) {
        BilinearGroup group;
        if (debug) {
            group = new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_3);
        } else {
            group = new BarretoNaehrigBilinearGroup(securityParameter);
        }

        doKeyGen(group, universe);
    }

    /**
     * Setup with pre-made group
     *
     * @param group    group to set up the scheme with
     * @param universe universe of attributes
     */
    public void doKeyGen(BilinearGroup group, Collection<? extends Attribute> universe) {
        // Public Parameter stuff
        pp = new ABECPWat11AsymSmallPublicParameters();

        pp.setBilinearGroup(group);
        Zp zp = new Zp(pp.getGroupG1().size());

        ZpElement alpha = zp.getUniformlyRandomUnit();
        ZpElement a = zp.getUniformlyRandomUnit();

        // generator g1 in G_1
        pp.setG1(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());
        // generator g2 in G_2
        pp.setG2(pp.getGroupG2().getUniformlyRandomNonNeutral().compute());
        // g_1^alpha for master secret key
        GroupElement g1Alpha = pp.getG1().pow(alpha);
        // eGgAlpha = e(g_1, g_2)^alpha = e(g_1^alpha, g_2)
        pp.setEGgAlpha(pp.getE().apply(g1Alpha, pp.getG2()).compute());
        // gA = g_1^a
        pp.setGA(pp.getG1().pow(a).compute());

        // msk = g^y
        msk = new ABECPWat11AsymSmallMasterSecret(g1Alpha.compute());

        Map<Attribute, GroupElement> attrs = new HashMap<>();
        // \for all x in univese T_x = RandomNonNeutral in G1
        for (Attribute attribute : universe) {
            attrs.put(attribute, pp.getGroupG1().getUniformlyRandomNonNeutral().compute());
        }
        pp.setAttrs(attrs);
    }

    public ABECPWat11AsymSmallPublicParameters getPublicParameters() {
        return pp;
    }

    public ABECPWat11AsymSmallMasterSecret getMasterSecret() {
        return msk;
    }
}
