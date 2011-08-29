package org.unitedid.jaas;

import java.io.Serializable;
import java.security.Principal;

public class OathHOTPPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 2178212116129504084L;
    private String name;

    public OathHOTPPrincipal(String name) {
        super();
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
