package org.unitedid.jaas;

import com.mongodb.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MongoDBFactory {
    /** Logger */
    private static final Logger log = LoggerFactory.getLogger(MongoDBFactory.class);

    private static Map<List<ServerAddress>, DB> mongoDbFactoryMap = new HashMap<List<ServerAddress>, DB>();

    private MongoDBFactory() {}

    /** Preferred read preference valid values */
    private static final Map<String, ReadPreference> MONGO_READ_PREF = Collections.unmodifiableMap(
            new HashMap<String, ReadPreference>() {{
        put("primary", ReadPreference.primary());
        put("primaryPreferred", ReadPreference.primaryPreferred());
        put("secondary", ReadPreference.secondary());
        put("secondaryPreferred", ReadPreference.secondaryPreferred());
        put("nearest", ReadPreference.nearest());
    }});

    /***
     * MongoDB factory
     *
     * @param hosts a list of <ServerAddress>hosts</ServerAddress>
     * @param database the database name
     * @param username the authentication username for the database
     * @param password the authentication password for the database
     * @param readPreference the read preference for replica sets,
     *                       possible values("primary", "primaryPreferred", "secondary", "secondaryPreferred", "nearest"
     * @return the db object
     */
    public static DB get(List<ServerAddress> hosts, String database, String username, String password,
                         String readPreference) {
        synchronized (mongoDbFactoryMap) {
            DB db = mongoDbFactoryMap.get(hosts);

            // Re-initiate a new connection if its not authenticated for some reason
            if (db != null && !db.isAuthenticated()) {
                log.debug("Re-initiating mongo db connection!");
                db.getMongo().close();
                mongoDbFactoryMap.remove(hosts);
                db = null;
            }

            if (db == null) {
                log.debug("Initiating a new mongo connection!");
                MongoClient connection = new MongoClient(hosts);

                if (readPreference != null || !readPreference.isEmpty()) {
                    log.debug("Set mongodb read preference to " + readPreference);
                    connection.setReadPreference(MONGO_READ_PREF.get(readPreference));
                }

                db = connection.getDB(database);
                if(!db.authenticate(username, password.toCharArray()))
                    throw new MongoException("Authentication failed, bad username or password!");
                mongoDbFactoryMap.put(hosts, db);
            }
            return db;
        }
    }
}
