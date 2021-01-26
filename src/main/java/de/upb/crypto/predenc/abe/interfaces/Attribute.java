package de.upb.crypto.predenc.abe.interfaces;

import de.upb.crypto.predenc.common.interfaces.policy.Policy;
import de.upb.crypto.predenc.common.interfaces.policy.PolicyFact;
import de.upb.crypto.math.hash.UniqueByteRepresentable;

public interface Attribute extends Policy, PolicyFact, UniqueByteRepresentable {

}
