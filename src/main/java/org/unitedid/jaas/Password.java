package org.unitedid.jaas;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class Password {
    private byte[] bytes;

    public Password(char[] password) {
        try {
            bytes = new String(password).getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Could not encode password as UTF-8");
        }
    }

    public String getString() {
        try {
            return new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not encode password as UTF-8");
        }
    }

    public char[] getChars() {
        return getString().toCharArray();
    }

    public void clearPassword() {
        Arrays.fill(bytes, (byte) 0x0);
        bytes = null;
    }

    /**
     * Provides a descriptive string representation of this instance.
     *
     * @return  string representation
     */
    @Override
    public String toString()
    {
        return new String(bytes);
    }
}
