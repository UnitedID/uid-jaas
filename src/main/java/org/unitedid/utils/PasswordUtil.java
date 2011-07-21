package org.unitedid.utils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordUtil {
    public static String getHashFromPassword(String password, String salt, int iterations, int length) {
        try {
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes("UTF-8"), iterations, length);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);

            return new String(secretKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Caught exception when attempting to hash password", e);
        }
    }
}
