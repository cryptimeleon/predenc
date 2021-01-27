package de.upb.crypto.predenc.enc.streaming;

import de.upb.crypto.craco.enc.streaming.StreamingEncryptionSchemeParams;
import de.upb.crypto.craco.enc.streaming.StreamingEncryptionSchemeTest;
import de.upb.crypto.craco.enc.streaming.params.StreamingAESParams;
import de.upb.crypto.predenc.enc.streaming.params.StreamingHybridCPLargeKEMParams;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Arrays;
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
