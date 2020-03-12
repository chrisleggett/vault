package com.pingidentity.gsa.devops.keymanagement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class VaultMasterKeyEncryptorUtil {


    public static final String K8S_SERVICE_ACCOUNT_TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token";
    public static final String K8S_SERVICE_ACCOUNT_NAMESPACE_PATH="/var/run/secrets/kubernetes.io/serviceaccount/namespace";

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

    public static String getK8sNamespaceFromFile() throws IOException {
        return getK8sArtifactFromFile(K8S_SERVICE_ACCOUNT_NAMESPACE_PATH);
    }

    public static String getK8sTokenFromFile() throws IOException {
        return getK8sArtifactFromFile(K8S_SERVICE_ACCOUNT_TOKEN_PATH);
    }

    private static String getK8sArtifactFromFile(String filepath) throws IOException {
        Path path = Paths.get(filepath);
        return Files.readAllLines(path).get(0);
    }

}
