package com.pingidentity.gsa.devops.keymanagement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Properties;

public class VaultMasterKeyEncryptorUtil {

    public static final String PINGACCESS_PRODUCT_NAME = "PingAccess";
    public static final String PINGFEDERATE_PRODUCT_NAME = "PingFederate";

    public static final String PRODUCT_ENVIRONMENT_VARIABLE = "PING_PRODUCT";

    private static final Log log = LogFactory.getLog("VaultMasterKeyEncryptorUtil");

    public static void printPropertiesFile(Properties prop){

        log.debug("***********************************");
        log.debug("***** vault.config.properties *****");
        for (String name : prop.stringPropertyNames()) {
            log.debug(name + " : " + prop.getProperty(name));
        }
        log.debug("***********************************");
    }

    public static String getProductName(){
        return (System.getenv(PRODUCT_ENVIRONMENT_VARIABLE) != null || System.getenv(PRODUCT_ENVIRONMENT_VARIABLE).isEmpty()) ? System.getenv(PRODUCT_ENVIRONMENT_VARIABLE) : "";
    }

}
