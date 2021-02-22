package org.cryptimeleon.predenc.abe;

import org.cryptimeleon.craco.common.attributes.SetOfAttributes;
import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.predenc.Predicate;

/**
 * A predicate that can check whether a given {@link Policy} is fulfilled by a {@link SetOfAttributes}.
 */
public class AbePredicate implements Predicate {

    /**
     * Returns result of evaluating the predicate.
     * @return true if the predicate is fulfilled, else false
     */
    @Override
    public boolean check(KeyIndex kind, CiphertextIndex cind) {
        if (kind instanceof SetOfAttributes && cind instanceof Policy)
            return ((Policy) cind).isFulfilled((SetOfAttributes) kind);
        if (cind instanceof SetOfAttributes && kind instanceof Policy)
            return ((Policy) kind).isFulfilled((SetOfAttributes) cind);
        return false;
    }
}
