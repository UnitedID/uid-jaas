package org.unitedid.utils;

import java.util.Map;

public class ConfigUtil {

    private ConfigUtil() {}

    public static String getOption(Map<String, ?> options, String key) {
        String option = null;
        option = (String) options.get(key);
        if (option == null)
            throw new IllegalArgumentException("Missing argument " + key);

        return option;
    }
}
