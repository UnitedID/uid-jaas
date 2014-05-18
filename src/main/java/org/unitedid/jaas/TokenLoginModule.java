package org.unitedid.jaas;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unitedid.auth.client.AuthClient;
import org.unitedid.auth.client.factors.OATHFactor;
import org.unitedid.auth.client.factors.YubiKeyFactor;
import org.unitedid.utils.ConfigUtil;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.*;

public class TokenLoginModule implements LoginModule {

    private final Logger log = LoggerFactory.getLogger(TokenLoginModule.class);

    /* Constant for login name stored in shared state. */
    public static final String LOGIN_NAME = "javax.security.auth.login.name";

    /* JAAS variables */
    private Subject subject;
    private Map<String, Object> sharedState;
    private CallbackHandler callbackHandler;
    private List<TokenPrincipal> principals = new ArrayList<TokenPrincipal>();

    /* Configuration options */
    private String authBackendURL;
    private String authUsername;
    private String authPassword;
    private Boolean softFail;


    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        log.debug("Initializing TokenLoginModule");

        this.subject = subject;
        this.sharedState = (Map<String, Object>) sharedState;
        this.callbackHandler = callbackHandler;

        if (options.get("softFail") != null) {
            softFail = Boolean.parseBoolean(ConfigUtil.getOption(options, "softFail"));
        }

        authBackendURL = ConfigUtil.getOption(options, "authBackendURL");
        authUsername = ConfigUtil.getOption(options, "authUsername");
        authPassword = ConfigUtil.getOption(options, "authPassword");
    }

    @Override
    public boolean login() throws LoginException {
        log.debug("Begin token login");

        NameCallback nameCallback = new NameCallback("Enter username: ");

        if (callbackHandler == null) {
            throw new LoginException("No callback handler available in login()");
        }

        List<String> otps = getTokens(nameCallback);
        if (otps.size() == 0) {
            if (softFail) {
                log.debug("No OTPs found and soft-fail is enabled. JAAS will now ignore this LoginModule.");
                return false;
            }
            throw new FailedLoginException("Token authentication failed, no OTPs available");
        }

        if (validateOtps(otps, nameCallback)) {
            return true;
        }

        throw new FailedLoginException("Token (2FA) authentication failed");
    }

    @Override
    public boolean commit() throws LoginException {
        log.trace("In commit()");
        for (TokenPrincipal principal : principals) {
            log.debug("Adding principal {}", principal);
            subject.getPrincipals().add(principal);
        }
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        log.trace("In abort()");
        for (TokenPrincipal principal : principals) {
            subject.getPrincipals().remove(principal);
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        log.trace("In logout()");
        for (TokenPrincipal principal : principals) {
            subject.getPrincipals().remove(principal);
        }
        return false;
    }

    private List<String> getTokens(NameCallback nameCallback) {
        MultiValuePasswordCallback mvPasswordCallback = new MultiValuePasswordCallback("Enter authentication tokens: ", false);
        List<String> result = new ArrayList<String>();
        try {
            callbackHandler.handle(new Callback[] {nameCallback, mvPasswordCallback});
            for (char[] c : mvPasswordCallback.getSecrets()) {
                String otp = new String(c);
                if (otp.length() < 6 && otp.length() > 8) {
                    log.debug("Skipping OTP, not a valid OATH-HOTP (expected length 6-8, but got {})", otp.length());
                } else if (!otp.matches("^[0-9]+$")) {
                    log.debug("Skipping OTP, not a valid OATH-HOTP (non digits not allowed)");
                } else {
                    result.add(otp);
                }
            }
        } catch (UnsupportedCallbackException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return result;
    }

    private boolean validateOtps(List<String> otps, NameCallback nameCallback) {
        boolean validated = false;

        log.debug("sharedState keys: {}", sharedState.keySet().toString());
        /* We need to iterate over all otps and all tokens found in sharedState */
        if (sharedState.containsKey("tokens")) {
            List<Map<String, Object>> tokens = (List<Map<String, Object>>) sharedState.get("tokens");

            log.debug("Processing token list, found {} entries", tokens.size());

            if (tokens.size() > 0) {
                for (String otp : otps) {
                    if (validateTokens(tokens, otp)) {
                        principals.add(new TokenPrincipal(nameCallback.getName()));
                        validated = true;
                    }
                }
            } else {
                log.debug("No tokens found for user {}", nameCallback.getName());
            }
        } else {
            log.debug("No tokens found in sharedState for user {}", nameCallback.getName());
        }

        return validated;
    }

    /***
     * Check otp against the authentication backend, if at least one token authenticate successfully we return true,
     * otherwise false.
     *
     * @param tokens
     * @param otp
     * @return
     */
    private boolean validateTokens(List<Map<String, Object>> tokens, String otp) {
        AuthClient authClient = new AuthClient(authBackendURL, authUsername, authPassword);

        for (Map<String, Object> token : tokens) {
            if (!(Boolean) token.get("active")) {
                continue;
            }

            String type = token.get("type").toString();
            if (type.equals("oathhotp") || type.equals("oathtotp")) {
                String nonce = token.get("nonce").toString();
                String credentialId = token.get("credentialId").toString();
                OATHFactor factor = new OATHFactor(type, nonce, otp, credentialId);

                if (authClient.authenticate(sharedState.get("userId").toString(), factor)) {
                    return true;
                }
            } else if (type.equals("yubikey")) {
                String nonce = token.get("nonce").toString();
                String credentialId = token.get("credentialId").toString();
                YubiKeyFactor factor = new YubiKeyFactor(type, nonce, otp, credentialId);

                if (authClient.authenticate(sharedState.get("userId").toString(), factor)) {
                    return true;
                }
            }
        }

        return false;
    }
}
