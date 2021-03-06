package org.cryptimeleon.predenc.enc.params;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.BigIntegerAttribute;
import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKeyPair;
import org.cryptimeleon.craco.enc.TestParams;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11MasterKeyShare;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11PublicParameters;
import org.cryptimeleon.predenc.abe.cp.large.distributed.DistributedABECPWat11Setup;
import org.cryptimeleon.predenc.abe.distributed.KeyShare;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

public class DistributedABECPWat11Params {

    public static ArrayList<TestParams> getParams() {
        Attribute[] stringAttributes = {
                new StringAttribute("A"), new StringAttribute("B"),
                new StringAttribute("C"), new StringAttribute("D"),
                new StringAttribute("E")
        };
        TestParams stringAttrParams = createGenericParams(stringAttributes);
        Attribute[] integerAttribute = {
                new BigIntegerAttribute(0), new BigIntegerAttribute(1),
                new BigIntegerAttribute(2), new BigIntegerAttribute(3),
                new BigIntegerAttribute(4)
        };
        TestParams integerAttrParams = createGenericParams(integerAttribute);

        ArrayList<TestParams> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }


    static int SERVER_COUNT = 5;
    static int SHARES_NEEDED = 3;

    static int MAX_NUMBER_ATTR = 10;
    static int SECURITY_PARAMETER = 80;

    static int MAX_MSP_COUNT = 10;

    public static TestParams createGenericParams(Attribute[] attributes) {

        DistributedABECPWat11Setup setup = new DistributedABECPWat11Setup();
        setup.doKeyGen(SECURITY_PARAMETER, MAX_NUMBER_ATTR, MAX_MSP_COUNT, SHARES_NEEDED, SERVER_COUNT, true);

        DistributedABECPWat11PublicParameters pp = setup.getPublicParameters();
        Set<DistributedABECPWat11MasterKeyShare> mskShares = setup.getMasterKeyShares();

        DistributedABECPWat11 scheme = new DistributedABECPWat11(pp);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);

        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey pk = scheme.generateEncryptionKey((CiphertextIndex) policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(attributes[0]);
        validAttributes.add(attributes[3]);
        validAttributes.add(attributes[4]);

        List<KeyShare> validKeyShares = new ArrayList<>();

        Iterator<DistributedABECPWat11MasterKeyShare> shareIterator = mskShares.iterator();
        for (int i = 0; i < SHARES_NEEDED; i++) {
            DistributedABECPWat11MasterKeyShare share = shareIterator.next();
            validKeyShares.add(scheme.generateKeyShare(share, validAttributes));
        }

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(attributes[0]);
        invalidAttributes.add(attributes[3]);

        List<KeyShare> invalidKeyShares = new ArrayList<>();

        shareIterator = mskShares.iterator();
        for (int i = 0; i < SHARES_NEEDED; i++) {
            DistributedABECPWat11MasterKeyShare share = shareIterator.next();
            invalidKeyShares.add(scheme.generateKeyShare(share, invalidAttributes));
        }


        DecryptionKey validSK = scheme.generateDecryptionKey(setup.getMasterSecret(), validAttributes);
//		DecryptionKey validSK = scheme.combineKeyShares(validKeyShares);
        DecryptionKey invalidSK = scheme.combineKeyShares(invalidKeyShares);

        EncryptionKeyPair validKeyPair = new EncryptionKeyPair(pk, validSK);
        EncryptionKeyPair invalidKeyPair = new EncryptionKeyPair(pk, invalidSK);

        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                pp.getGroupGT().getUniformlyRandomElement()));

        return new TestParams(scheme, supplier, validKeyPair, invalidKeyPair);
    }

}
