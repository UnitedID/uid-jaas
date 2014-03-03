package org.unitedid.jaas;

import com.mongodb.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unitedid.utils.ConfigUtil;
import org.unitedid.utils.PasswordUtil;
import org.unitedid.yhsm.ws.YubiHSMErrorException_Exception;
import org.unitedid.yhsm.ws.client.YubiHSMValidationClient;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
    private String mongoReadPref = "primary";

    // PBKDF2 iterations and length
    private int pbkdf2Iterations = 0;
    private int pbkdf2Length = 0;

    private String wsdlValidationURL;
    private int yubiHSMKeyHandle = 0;

    private Subject subject;
    private Map<String, Object> sharedState;
    private CallbackHandler callbackHandler;

    private String username;
    private UIDPrincipal user;

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        log.debug("Initializing UIDLoginModule.");

        this.subject = subject;
        this.sharedState = (Map<String, Object>) sharedState;
        this.callbackHandler = callbackHandler;

        String mongoHosts = ConfigUtil.getOption(options, "mongoHosts");
        for (String host : mongoHosts.split(",")) {
            try {
                this.mongoHosts.add(new ServerAddress(host));
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        }

        mongoDb = ConfigUtil.getOption(options, "mongoDb");
        mongoCollection = ConfigUtil.getOption(options, "mongoCollection");
        mongoUser = ConfigUtil.getOption(options, "mongoUser");
        mongoPassword = ConfigUtil.getOption(options, "mongoPassword");
        if (options.get("mongoReadPref") != null) {
            mongoReadPref = ConfigUtil.getOption(options, "mongoReadPref");
        }
        pbkdf2Iterations = Integer.parseInt(ConfigUtil.getOption(options, "pbkdf2Iterations"));
        pbkdf2Length = Integer.parseInt(ConfigUtil.getOption(options, "pbkdf2Length"));
        yubiHSMKeyHandle = Integer.parseInt(ConfigUtil.getOption(options, "yubiHSMKeyHandle"));
        wsdlValidationURL = ConfigUtil.getOption(options, "wsdlValidationURL");
    }

    public boolean login() throws LoginException {
        NameCallback nameCallback = new NameCallback("Enter username: ");
        PasswordCallback passwordCallback = new PasswordCallback("Enter password: ", true);
        getCredentials(nameCallback, passwordCallback, true);
        Password pass = new Password(passwordCallback.getPassword());
        passwordCallback.clearPassword();
        username = nameCallback.getName().toLowerCase();

        // Fetch mongo object from factory
        DB db = MongoDBFactory.get(mongoHosts, mongoDb, mongoUser, mongoPassword, mongoReadPref);
        DBCollection collection = db.getCollection(mongoCollection);

        // Query username or email address since we don't know which one was used
        DBObject query = QueryBuilder.start().or(
                new BasicDBObject("username", username),
                new BasicDBObject("mail", username),
                new BasicDBObject("mailAlias", username)).get();

        DBObject result = collection.findOne(query);
        if (result == null) {
            throw new FailedLoginException("User not found: " + username);
        } else if (!(Boolean) result.get("active")) {
            throw new FailedLoginException("User not activated: " + username);
        }

        String aead = (String) result.get("password");
        String nonce = (String) result.get("nonce");
        String salt = (String) result.get("salt");
        String hashedPassword = PasswordUtil.getHashFromPassword(pass.toString(), salt, pbkdf2Iterations, pbkdf2Length);
        pass.clearPassword();

        try {
            YubiHSMValidationClient hsm = new YubiHSMValidationClient(wsdlValidationURL);
            if(!hsm.validateAEAD(nonce, yubiHSMKeyHandle, aead, hashedPassword)) {
                throw new FailedLoginException("AEAD validation failed for user: " + username);
            }
        } catch (YubiHSMErrorException_Exception e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        // Get available tokens and pass them on to the next JAAS module through sharedState
        if (result.containsField("tokens") ) {
            List<Map<String, Object>> tokens = new ArrayList<Map<String, Object>>();
            // Convert DBObject list to a regular list of Linkedhashmap
            for (DBObject token : (List<DBObject>) result.get("tokens")) {
                tokens.add(token.toMap());
            }
            sharedState.put("tokens", tokens);
        }

        user = new UIDPrincipal(username);
        sharedState.put(LOGIN_NAME, username);
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

            log.debug("Authentication has completed successfully");
        }
        clearState();
        commitSucceeded = true;
        return true;
    }

    public boolean abort() throws LoginException {
        log.debug("Authentication has not completed successfully");

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

        log.debug("Subject is being logged out");

        return true;
    }

    private void clearState() {
        subject = null;
        callbackHandler = null;
        username = null;
        sharedState = null;
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
