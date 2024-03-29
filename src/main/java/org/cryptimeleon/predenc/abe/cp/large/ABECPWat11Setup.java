package org.cryptimeleon.predenc.abe.cp.large;

import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.type1.supersingular.SupersingularBilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;
import org.cryptimeleon.predenc.WatersHash;

/**
 * Contains methods for generating public parameters and master secret for the scheme.
 */
public class ABECPWat11Setup {
    private ABECPWat11PublicParameters pp;
    private ABECPWat11MasterSecret msk;

    /**
     * Generate public parameters and the master secret.
     * <p>
     * Sets up public parameters and the master secret for a given security parameter
     * securityParameter. The parameter n specifies the maximum number of
     * attributes per key. The parameter l_max specifies the maximum number of
     * rows per MSPs. The parameter watersHash selects between two possible hash
     * functions: Waters Hash function or the hash function from the group
     * factory. The former yields a secure construction in the standard model
     * while the latter might be only secure in the random oracle model.
     * Typically, setting watersHash to false provides much faster
     * implementations, especially for large n and l_max.
     * <p>
     * To enable debugging modus, set debug to true. WARNING: This results in an
     * insecure instantiation of the underlying groups.
     *
     * @param securityParameter
     * @param n                 maximum number of attributes per key.
     * @param l_max             maximum number of rows per MSP
     * @param watersHash        the hash function
     * @param debug             enable debugging.
     */
    public void doKeyGen(int securityParameter, int n, int l_max, boolean watersHash, boolean debug) {
        // Generate bilinear group
        BilinearGroup group;
        if (debug) {
            group = new DebugBilinearGroup(RandomGenerator.getRandomPrime(securityParameter), BilinearGroup.Type.TYPE_1);
        } else {
            group = new SupersingularBilinearGroup(securityParameter);
        }

        doKeyGen(group, n, l_max, watersHash);
    }

    /**
     * Setup with Waters Hash function. Secure in standard model.
     *
     * @param securityParameter
     * @param n                 maximum number of attributes per key
     * @param l_max             maximum size of MSP
     */
    public void doKeyGenWatersHash(int securityParameter, int n, int l_max) {
        doKeyGen(securityParameter, n, l_max, true, false);
    }

    /**
     * Setup with cryptographic hash function. Secure in random oracle model.
     *
     * @param securityParameter
     */
    public void doKeyGenRandomOracle(int securityParameter) {
        doKeyGen(securityParameter, Integer.MAX_VALUE / 2, Integer.MAX_VALUE / 2, false, false);
    }

    /**
     * Setup with a pre-made group
     *
     * @param group group used for the scheme
     * @param n     maximum number of attributes per key
     * @param lMax  maximum size of MSP
     */
    public void doKeyGen(BilinearGroup group, int n, int lMax, boolean watersHash) {
        pp = new ABECPWat11PublicParameters();

        pp.setN(n);
        pp.setlMax(lMax);

        if (!watersHash) {
            pp.setHashToG1(group.getHashIntoG1());
        } else {
            pp.setHashToG1(new WatersHash(pp.getGroupG1(), n + lMax));
        }
        pp.setBilinearGroup(group);

        Zp zp = new Zp(pp.getGroupG1().size());

        // Do the scheme setup stuff
        ZpElement y = zp.getUniformlyRandomUnit();
        ZpElement a = zp.getUniformlyRandomUnit();
        pp.setG(pp.getGroupG1().getUniformlyRandomNonNeutral().compute());
        // Y = e(g,g)^y = e(g^y, g)
        GroupElement gY = pp.getG().pow(y).compute();
        pp.setY(pp.getE().apply(gY, pp.getG()));
        pp.setgA(pp.getG().pow(a).compute());
        msk = new ABECPWat11MasterSecret(gY);
    }

    /**
     * Returns the public parameter generated by {@link #doKeyGen} or null if no
     * public parameters were generated
     *
     * @return the public parameters that can be used for setting up the {@link ABECPWat11}
     */
    public ABECPWat11PublicParameters getPublicParameters() {
        return pp;
    }

    /**
     * The master secret of this scheme. This is needed for generating a {@link ABECPWat11DecryptionKey} in the
     * {@link ABECPWat11}
     *
     * @return the master secret
     */
    public ABECPWat11MasterSecret getMasterSecret() {
        return msk;
    }
}
