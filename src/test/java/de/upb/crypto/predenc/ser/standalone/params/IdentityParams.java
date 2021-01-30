package de.upb.crypto.predenc.ser.standalone.params;

import de.upb.crypto.craco.common.attributes.BigIntegerAttribute;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.predenc.abe.fuzzy.large.Identity;

public class IdentityParams {
    public static StandaloneTestParams get() {
        Identity id = new Identity(
                new BigIntegerAttribute(1), new BigIntegerAttribute(2),
                new BigIntegerAttribute(4)
        );
        return new StandaloneTestParams(Identity.class, id);
    }

}
