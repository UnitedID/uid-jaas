package org.unitedid.jaas;

import com.mongodb.*;
import com.yubico.jaas.MultiValuePasswordCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unitedid.utils.ConfigUtil;
import org.unitedid.yhsm.ws.YubiHSMErrorException_Exception;
import org.unitedid.yhsm.ws.client.YubiHSMValidationClient;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OathHOTPLoginModule implements LoginModule {

    private final Logger log = LoggerFactory.getLogger(OathHOTPLoginModule.class);

    /* Constant for login name stored in shared state. */
    public static final String LOGIN_NAME = "javax.security.auth.login.name";

    /* JAAS variables */
    private Subject subject;
    private Map<String, Object> sharedState;
    private CallbackHandler callbackHandler;

    private List<OathHOTPPrincipal> principals = new ArrayList<OathHOTPPrincipal>();

    /* Configuration options */
    private String wsdlValidationURL;
    private int yubiHSMKeyHandle = 0;
    private boolean softFail = true;
    private int lookAhead = 1;

    /* Mongo DB related */
    private List<ServerAddress> mongoHosts = new ArrayList<ServerAddress>();
    private String mongoDb = null;
    private String mongoCollection = null;
    private String mongoUser = null;
    private String mongoPassword = null;
    private String mongoReadPref = "primary";


    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        log.debug("Initializing OathHOTPLoginModule");

        this.subject = subject;
        this.sharedState = (Map<String, Object>) sharedState;
        this.callbackHandler = callbackHandler;

        wsdlValidationURL = ConfigUtil.getOption(options, "wsdlValidationURL");
        yubiHSMKeyHandle = Integer.parseInt(ConfigUtil.getOption(options, "yubiHSMKeyHandle"));

        if (options.get("lookAhead") != null) {
            lookAhead = Integer.parseInt(ConfigUtil.getOption(options, "lookAhead"));
        }

        if (options.get("softFail") != null) {
            softFail = Boolean.parseBoolean(ConfigUtil.getOption(options, "softFail"));
        }

        String mongoHosts = ConfigUtil.getOption(options, "mongoHosts");
        for (String host : mongoHosts.split(",")) {
            try {
                this.mongoHosts.add(new ServerAddress(host));
            } catch (UnknownHostException e) {
                throw new RuntimeException(e);
            }
        }

        mongoDb = ConfigUtil.getOption(options, "mongoDb");
        mongoCollection = ConfigUtil.getOption(options, "mongoCollection");
        mongoUser = ConfigUtil.getOption(options, "mongoUser");
        mongoPassword = ConfigUtil.getOption(options, "mongoPassword");
        if (options.get("mongoReadPref") != null) {
            mongoReadPref = ConfigUtil.getOption(options, "mongoReadPref");
        }
    }

    public boolean login() throws LoginException {
        log.debug("Begin OATH-HOTP login");

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
            throw new FailedLoginException("OATH-HOTP authentication failed, no OTPs available");
        }

        if (validateOtps(otps, nameCallback)) {
            return true;
        }

        throw new FailedLoginException("OATH-HOTP authentication failed");
    }

    public boolean commit() throws LoginException {
        log.trace("In commit()");
        for (OathHOTPPrincipal principal : principals) {
            log.debug("Adding principal {}", principal);
            subject.getPrincipals().add(principal);
        }
        return true;
    }

    public boolean abort() throws LoginException {
        log.trace("In abort()");
        for (OathHOTPPrincipal principal : principals) {
            subject.getPrincipals().remove(principal);
        }
        return true;
    }

    public boolean logout() throws LoginException {
        log.trace("In logout()");
        for (OathHOTPPrincipal principal : principals) {
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
                    if (validateOathHOTP(tokens, otp)) {
                        principals.add(new OathHOTPPrincipal(nameCallback.getName()));
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

    private boolean validateOathHOTP(List<Map<String, Object>> tokens, String otp) {
        for (Map<String, Object> token : tokens) {
            if ((token.get("type").equals("oathhotp") || token.get("type").equals("googlehotp")) && token.get("active").equals(true)) {
                int newCounter;
                String tokenId = (String) token.get("tokId");
                String nonce = (String) token.get("nonce");
                String aead = (String) token.get("aead");
                int counter = (Integer) token.get("counter");

                YubiHSMValidationClient hsm = new YubiHSMValidationClient(wsdlValidationURL);
                try {
                    newCounter = hsm.validateOathHOTP(nonce, yubiHSMKeyHandle, aead, counter, otp, lookAhead);
                } catch (YubiHSMErrorException_Exception e) {
                    throw new RuntimeException(e);
                }

                if (newCounter != 0) {
                    updateTokenCounter(tokenId, newCounter);
                    return true;
                }
            }
        }

        return false;
    }

    private void updateTokenCounter(String tokenId, int counter) {
        try {
            String loginName = (String) sharedState.get(LOGIN_NAME);

            DB db = MongoDBFactory.get(mongoHosts, mongoDb, mongoUser, mongoPassword, mongoReadPref);
            DBCollection collection = db.getCollection(mongoCollection);

            DBObject searchQuery = QueryBuilder.start().or(
                    new BasicDBObject("username", loginName),
                    new BasicDBObject("mail", loginName)).and("tokens.tokId").is(tokenId).get();

            BasicDBObject set = new BasicDBObject();
            set.put("$set", new BasicDBObject("tokens.$.counter", counter));
            collection.update(searchQuery, set);
        } catch(Exception e)  {
            throw new RuntimeException(e);
        }
    }
}
