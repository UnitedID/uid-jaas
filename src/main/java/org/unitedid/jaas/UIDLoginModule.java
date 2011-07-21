package org.unitedid.jaas;

import com.mongodb.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unitedid.utils.PasswordUtil;
import org.unitedid.yhsm.YubiHSM;
import org.unitedid.yhsm.internal.YubiHSMCommandFailedException;
import org.unitedid.yhsm.internal.YubiHSMErrorException;
import org.unitedid.yhsm.internal.YubiHSMInputException;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.awt.*;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class UIDLoginModule implements LoginModule {

    private final Logger log = LoggerFactory.getLogger(UIDLoginModule.class);

    /** Constant for login name stored in shared state. */
    public static final String LOGIN_NAME = "javax.security.auth.login.name";

    /** Constant for login password stored in shared state. */
    public static final String LOGIN_PASSWORD = "javax.security.auth.login.password";

    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    // Mongo DB related
    private List<ServerAddress> mongoHosts = new ArrayList<ServerAddress>();
    private String mongoDb = null;
    private String mongoCollection = null;
    private String mongoUser = null;
    private String mongoPassword = null;

    // PBKDF2 iterations and length
    private int pbkdf2Iterations = 0;
    private int pbkdf2Length = 0;

    private String yubiHSMDevice = null;
    private int yubiHSMKeyHandle = 0;

    private Subject subject;
    private Map<String, ?> sharedState;
    private CallbackHandler callbackHandler;

    private String username;
    private UIDPrincipal user;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        log.debug("Initializing UIDLoginModule.");

        this.subject = subject;
        this.sharedState = sharedState;
        this.callbackHandler = callbackHandler;

        String mongoHosts = getOption(options, "mongoHosts");
        for (String host : mongoHosts.split(",")) {
            try {
                this.mongoHosts.add(new ServerAddress(host));
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        }

        mongoDb = getOption(options, "mongoDb");
        mongoCollection = getOption(options, "mongoCollection");
        mongoUser = getOption(options, "mongoUser");
        mongoPassword = getOption(options, "mongoPassword");
        pbkdf2Iterations = Integer.parseInt(getOption(options, "pbkdf2Iterations"));
        pbkdf2Length = Integer.parseInt(getOption(options, "pbkdf2Length"));
        yubiHSMDevice = getOption(options, "yubiHSMDevice");
        yubiHSMKeyHandle = Integer.parseInt(getOption(options, "yubiHSMKeyHandle"));
    }

    public boolean login() throws LoginException {
        NameCallback nameCallback = new NameCallback("Enter username: ");
        PasswordCallback passwordCallback = new PasswordCallback("Enter password: ", true);
        getCredentials(nameCallback, passwordCallback, true);
        Password pass = new Password(passwordCallback.getPassword());
        passwordCallback.clearPassword();
        username = nameCallback.getName();

        // Fetch mongo object from factory
        DB db = MongoDBFactory.get(mongoHosts, mongoDb, mongoUser, mongoPassword);
        DBCollection collection = db.getCollection(mongoCollection);

        BasicDBObject query = new BasicDBObject();
        query.put("username", username);

        DBObject result = collection.findOne(query);
        if (result == null) {
            throw new FailedLoginException("User not found: " + username);
        } else if (!(Boolean) result.get("active")) {
            throw new FailedLoginException("User not activated: " + username);
        }

        String hashedPassword = PasswordUtil.getHashFromPassword(pass.toString(), (String) result.get("salt"), pbkdf2Iterations, pbkdf2Length);
        pass.clearPassword();
        String aead = (String) result.get("password");
        String nonce = (String) result.get("nonce");

        try {
            // YubiHSM
            YubiHSM hsm = new YubiHSM(yubiHSMDevice, 1);
            if (!hsm.validateAEAD(nonce, yubiHSMKeyHandle, aead, hashedPassword)) {
                throw new FailedLoginException("AEAD validation failed for user: " + username);
            }
        } catch (YubiHSMErrorException e) {
            throw new RuntimeException(e);
        } catch (YubiHSMCommandFailedException e) {
            throw new RuntimeException(e);
        } catch (YubiHSMInputException e) {
            // This exception indicate that the password is wrong because the expected length of aead and password are wrong
            throw new FailedLoginException("AEAD validation failed for user: " + username);
        }

        user = new UIDPrincipal(username);
        succeeded = true;
        return true;
    }

    public boolean commit() throws LoginException {
        if (!succeeded) {
            return false;
        } else {
            if (subject.isReadOnly()) {
                clearState();
                throw new LoginException("Subject is read only");
            }

            if (!subject.getPrincipals().contains(user)) {
                subject.getPrincipals().add(user);
            }

            if (log.isDebugEnabled()) {
                log.debug("Authentication has completed successfully");
            }
        }
        clearState();
        commitSucceeded = true;
        return true;
    }

    public boolean abort() throws LoginException {
        if (log.isDebugEnabled()) {
            log.debug("Authentication has not completed successfully");
        }
        if (!succeeded) {
            return false;
        } else if (!commitSucceeded) {
            succeeded = false;
            clearState();
            user = null;
        } else {
            logout();
        }

        return true;
    }

    public boolean logout() throws LoginException {
        if (subject.isReadOnly()) {
            clearState();
            throw new LoginException("Subject is read only");
        }

        subject.getPrincipals().remove(user);
        succeeded = false;
        commitSucceeded = false;
        user = null;

        if (log.isDebugEnabled()) {
            log.debug("Subject is being logged out");
        }
        return true;
    }

    private void clearState() {
        subject = null;
        callbackHandler = null;
        username = null;
    }

    private String getOption(Map<String, ?> options, String key) {
        String option = null;
        option = (String) options.get(key);
        if (option == null)
            throw new IllegalArgumentException("Missing argument " + key);

        return option;
    }

    protected void getCredentials(NameCallback nameCallback, PasswordCallback passwordCallback, boolean useCallback) throws LoginException {
        try {
            if (!useCallback) {
                nameCallback.setName((String) sharedState.get(LOGIN_NAME));
                passwordCallback.setPassword((char[]) sharedState.get(LOGIN_PASSWORD));
            } else if (callbackHandler != null) {
                callbackHandler.handle(new Callback[] {nameCallback, passwordCallback});
            } else {
                throw new LoginException("No CallbackHandler available");
            }
        } catch (IOException e) {
            log.error("Error reading data from callback handler", e);
        } catch (UnsupportedCallbackException e) {
            log.error("Unsupported callback", e);
        }
    }
}
