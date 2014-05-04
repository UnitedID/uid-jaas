package org.unitedid.jaas;

import java.io.Serializable;
import java.security.Principal;

public class TokenPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 1001701204144522222L;
    private String name;

    public TokenPrincipal(String name) {
        super();
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
