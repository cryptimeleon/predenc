package org.cryptimeleon.predenc.enc.streaming;

import org.cryptimeleon.craco.enc.streaming.StreamingEncryptionSchemeParams;
import org.cryptimeleon.craco.enc.streaming.StreamingEncryptionSchemeTest;
import org.cryptimeleon.predenc.enc.streaming.params.StreamingHybridCPLargeKEMParams;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;

public class StreamingEncryptionSchemeSubTest extends StreamingEncryptionSchemeTest {
    public StreamingEncryptionSchemeSubTest(StreamingEncryptionSchemeParams params) {
        super(params);
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<StreamingEncryptionSchemeParams> data() {
        ArrayList<StreamingEncryptionSchemeParams> toReturn = new ArrayList<>();
        toReturn.addAll(StreamingHybridCPLargeKEMParams.get());
        return toReturn;
    }
}
