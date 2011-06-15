package org.unitedid.jaas;

import java.io.Serializable;
import java.security.Principal;

public class UIDPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 8203484237272899779L;
    private String name;

    public UIDPrincipal(String name) {
        super();
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
