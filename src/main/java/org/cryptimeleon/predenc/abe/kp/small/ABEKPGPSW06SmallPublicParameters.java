package org.cryptimeleon.predenc.abe.kp.small;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.predenc.abe.cp.small.ABECPWat11SmallSetup;

import java.util.Map;
import java.util.Objects;

/**
 * The parameters for the {@link ABEKPGPSW06Small} generated in the
 * {@link ABECPWat11SmallSetup}.
 */
public class ABEKPGPSW06SmallPublicParameters implements PublicParameters {

    // in groupG1
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g;
    // Attribute in universe T_i in groupG1
    @Represented(restorer = "foo -> bilinearGroup::getG1")
    private Map<Attribute, GroupElement> T;
    // in groupGT
    @Represented(restorer = "bilinearGroup::getGT")
    private GroupElement Y;

    @Represented
    private BilinearGroup bilinearGroup;

    public ABEKPGPSW06SmallPublicParameters() {
    }

    public ABEKPGPSW06SmallPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
    }

    public Map<Attribute, GroupElement> getT() {
        return T;
    }

    public void setT(Map<Attribute, GroupElement> t) {
        T = t;
    }

    public GroupElement getY() {
        return Y;
    }

    public void setY(GroupElement y) {
        Y = y;
    }

    public Group getGroupG1() {
        return bilinearGroup.getG1();
    }

    public Group getGroupGT() {
        return bilinearGroup.getGT();
    }

    public BilinearMap getE() {
        return bilinearGroup.getBilinearMap();
    }

    public void setBilinearGroup(BilinearGroup bilGroup) {
        bilinearGroup = bilGroup;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABEKPGPSW06SmallPublicParameters other = (ABEKPGPSW06SmallPublicParameters) obj;
        return Objects.equals(g, other.g)
                && Objects.equals(T, other.T)
                && Objects.equals(Y, other.Y)
                && Objects.equals(bilinearGroup, other.bilinearGroup);
    }

    @Override
    public int hashCode() {
        return Objects.hash(g, T, Y, bilinearGroup);
    }
}
