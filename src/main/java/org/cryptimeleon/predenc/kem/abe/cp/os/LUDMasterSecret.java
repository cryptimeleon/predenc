package org.cryptimeleon.predenc.kem.abe.cp.os;

import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;
import org.cryptimeleon.predenc.MasterSecret;


/**
 * Class for master secret key alpha in Zp.
 */
public class LUDMasterSecret implements MasterSecret {

    private ZpElement alpha;

    public LUDMasterSecret(ZpElement alpha) {
        this.alpha = alpha;
    }

    public ZpElement getSecretExponent() {
        return alpha;
    }

    @Override
    public Representation getRepresentation() {
        return alpha.getRepresentation();
    }
}
