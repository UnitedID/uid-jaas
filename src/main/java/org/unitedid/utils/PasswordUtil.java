package org.unitedid.utils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordUtil {
    public static String getHashFromPassword(String password, String salt, int iterations, int length) {
        try {
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes("UTF-8"), iterations, length);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
            char[] hash = Hex.encodeHex(new Base64().encode(secretKey.getEncoded()));

            return new String(hash);
        } catch (Exception e) {
            throw new RuntimeException("Caught exception when attempting to hash password", e);
        }
    }
}
