package org.unitedid.jaas;

import com.mongodb.DB;
import com.mongodb.Mongo;
import com.mongodb.MongoException;
import com.mongodb.ServerAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MongoDBFactory {
    /** Logger */
    private static final Logger log = LoggerFactory.getLogger(MongoDBFactory.class);

    private static Map<List<ServerAddress>, DB> mongoDbFactoryMap = new HashMap<List<ServerAddress>, DB>();

    private MongoDBFactory() {}

    public static DB get(List<ServerAddress> hosts, String database, String username, String password) {
        synchronized (mongoDbFactoryMap) {
            DB db = mongoDbFactoryMap.get(hosts);

            if (db == null) {
                log.debug("Initiating a new mongo connection!");
                Mongo connection = new Mongo(hosts);
                db = connection.getDB(database);
                if(!db.authenticate(username, password.toCharArray()))
                    throw new MongoException("Authentication failed, bad username or password!");
                db.slaveOk();
                mongoDbFactoryMap.put(hosts, db);
            }
            return db;
        }
    }
}
