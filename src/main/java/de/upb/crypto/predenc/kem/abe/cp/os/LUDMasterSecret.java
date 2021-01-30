package de.upb.crypto.predenc.kem.abe.cp.os;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;
import de.upb.crypto.predenc.MasterSecret;


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
