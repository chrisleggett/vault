package com.pingidentity.gsa.devops.keymanagement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Properties;

public class VaultMasterKeyEncryptorUtil {

    private static final Log log = LogFactory.getLog("VaultMasterKeyEncryptorUtil");

    public static void printPropertiesFile(Properties prop){

        log.debug("***********************************");
        log.debug("***** vault.config.properties *****");
        for (String name : prop.stringPropertyNames()) {
            log.debug(name + " : " + prop.getProperty(name));
        }
        log.debug("***********************************");


    }

}
