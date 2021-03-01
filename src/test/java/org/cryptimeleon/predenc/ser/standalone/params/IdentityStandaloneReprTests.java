package org.cryptimeleon.predenc.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.predenc.abe.fuzzy.large.Identity;

public class IdentityStandaloneReprTests extends StandaloneReprSubTest {

    Identity id;

    public IdentityStandaloneReprTests() {
        id = new Identity(
                new BigIntegerAttribute(1), new BigIntegerAttribute(2),
                new BigIntegerAttribute(4)
        );
    }

    public void testIdentity() {
        test(id);
    }
}
