package com.pingidentity.gsa.devops.keymanagement;

import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.response.*;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;
import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;

import com.pingidentity.sdk.key.MasterKeyEncryptor;
import com.pingidentity.sdk.key.MasterKeyEncryptorException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class VaultMasterKeyEncryptor implements MasterKeyEncryptor {

    private final Log log = LogFactory.getLog(this.getClass());

    private VaultConfigData vaultConfigData;
    private Vault vault;
    private boolean vaultReady = false;
    private String keyId;
    private int maxRetries = 0;

    public VaultMasterKeyEncryptor(){

        log.debug("Creating the VaultMasterKeyEncryptor.");

        try {

            //load the vault parameters from the properties file
            this.vaultConfigData = loadVaultConfigData();

            // We need to get the roleid client token. This will be used in subsequent requests.
            this.vaultConfigData.setVaultToken(getTokenFromRoleId(vaultConfigData.getVaultRoleId()));

            //set the vaultConfig object
            log.debug("Loading the vault configuration.");
            VaultConfig vaultConfig = setVaultConfig(vaultConfigData);

            // set the vault driver object
            this.vault = new Vault(vaultConfig,1);

            //get the vault health
            HealthResponse healthResponse = getHealthResponse();

            if(healthResponse.getInitialized() && !healthResponse.getSealed()) {
                log.debug("The vault is initialized and unsealed. Ready...");
                this.maxRetries = vaultConfigData.getMaxRetry();
                this.vaultReady = true;
            }
            else {
                throw new VaultMasterKeyEncryptorException("The vault is not initialized or unsealed");
            }

        } catch(VaultException | VaultMasterKeyEncryptorException ve){
            log.error(ve);
        }
    }


    @Override
    public String initialize(String keyId) throws MasterKeyEncryptorException {

        log.debug("Initializing the vault transit key: " + keyId + ".");

        if(this.vaultReady){
            boolean transitEnabled = isTransitEngineEnabled();

            if(!transitEnabled) {
                // Lets enable the transit secrets engine
                RestResponse response = enableTransitEngine();
                if (response.getStatus() >= 200 && response.getStatus() <= 299) {
                    log.debug("This PingFederate node initialized the transit engine.");
                } else {
                    String errorMsg = new String(response.getBody());
                    log.error("Error: Unable to initialize the transit engine. Msg: " + errorMsg);
                    throw new VaultMasterKeyEncryptorException("Error: Unable to initialize the transit engine. Msg: " + errorMsg);
                }
            }

            if(keyId == null || keyId.isEmpty()){
                log.debug("The keyId is null or empty. Generating a new keyId.");
                this.keyId = vaultConfigData.getTransitKeyName();
            } else {
                this.keyId = keyId;
            }

            if(vaultConfigData.isCreateEncKey()) {
                log.debug("The keyId value: " + this.keyId);
                if (createTransitKey(this.keyId)) {
                    keyId = this.keyId;
                }
            }
        } else {
            log.error("The vault is not ready. " +
                            "Ensure that this PingFederate node can reach the vault at the following address: " + vaultConfigData.getVaultAddress() +
                            " and the vault is not sealed.");
            throw new VaultMasterKeyEncryptorException("The vault is not ready. " +
                    "Ensure that this PingFederate node can reach the vault at the following address: " + vaultConfigData.getVaultAddress() +
                    " and the vault is not sealed.");
        }
        return keyId;
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws MasterKeyEncryptorException {

        log.debug("Encrypting the master key...");

        //Base64 encode the plain text.
        String plainTextString = new String(Base64.getEncoder().encode(plainText));
        log.debug("Encoded plain text: " + plainTextString);

        //Store the key before encrypting. This helps with config portability and can be used as a backup for restoration. :)
        log.debug("Storing key in secrets engine.");
        storeKey(plainTextString);

        //Generate json payload.
        String payload = Json.object()
                .add("plaintext", plainTextString)
                .toString();
        log.debug("payload: " + payload);

        byte[] cipherText = null;

        try{
            Map<String, Object> payloadMap = new HashMap<>();
            payloadMap.put("plaintext", plainTextString);
            LogicalResponse logicalResponse = this.vault.logical().write("transit/encrypt/" + this.keyId, payloadMap);
            JsonObject jsonResponse = logicalResponse.getDataObject();
            String cipherTextString = jsonResponse.get("ciphertext").asString();
            cipherText = cipherTextString.getBytes();

        } catch(VaultException ve) {
            log.error(ve);
        }

        assert cipherText != null;
        log.debug("Cipher Text: " + new String(cipherText));
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws MasterKeyEncryptorException {

        log.debug("Decrypting the master key...");

        byte[] decodedPlainText;

        try{
            String cipherTextString = new String(cipherText, StandardCharsets.UTF_8);
            log.debug("cipher text: " + cipherTextString);
            Map<String, Object> payloadMap = new HashMap<>();
            payloadMap.put("ciphertext", cipherTextString);
            LogicalResponse logicalResponse = this.vault.logical().write("transit/decrypt/" + this.keyId, payloadMap);
            JsonObject jsonResponse = logicalResponse.getDataObject();
            decodedPlainText = Base64.getDecoder().decode(jsonResponse.get("plaintext").asString().getBytes());

        } catch(VaultException ve){
            log.error(ve);
            throw new MasterKeyEncryptorException("Error: Unable to decrypt the master key.", ve);
        }
        log.debug("Decrypted and Decoded Text: " + new String(decodedPlainText));
        return decodedPlainText;
    }

    private VaultConfigData loadVaultConfigData() throws VaultMasterKeyEncryptorException {

        VaultConfigData vaultConfigData = new VaultConfigData();
        String productName = VaultMasterKeyEncryptorUtil.getProductName();
        String filepath = "";

        if(productName.isEmpty()){
            log.error("Error: Unable to determine product name from environment variable.");
            throw new VaultMasterKeyEncryptorException("Error: Unable to determine product name from environment variable.");
        } else if(productName.equals(VaultMasterKeyEncryptorUtil.PINGFEDERATE_PRODUCT_NAME)){
            filepath = "/opt/out/instance/server/default/conf/vault.config.properties";
        } else if(productName.equals(VaultMasterKeyEncryptorUtil.PINGACCESS_PRODUCT_NAME)){
            filepath = "/opt/out/instance/conf/vault.config.properties";
        }

        try (InputStream input = new FileInputStream(filepath)) {

            Properties prop = new Properties();

            // load a properties file
            prop.load(input);

            VaultMasterKeyEncryptorUtil.printPropertiesFile(prop);

            // get the java property value
            vaultConfigData.setVaultAddress(prop.getProperty("vault.api.address"));
            vaultConfigData.setTransitKeyName(prop.getProperty("vault.transit.keyname"));
            vaultConfigData.setVaultRoleId(prop.getProperty("vault.auth.roleid"));
            vaultConfigData.setVerifySSL(Boolean.getBoolean(prop.getProperty("vault.api.verifyssl")));
            vaultConfigData.setOpenTimeoutSeconds(Integer.parseInt(prop.getProperty("vault.api.opentimeout")));
            vaultConfigData.setReadTimeoutSeconds(Integer.parseInt(prop.getProperty("vault.api.readtimeout")));
            vaultConfigData.setMaxRetry(Integer.parseInt(prop.getProperty("vault.api.maxretry")));
            vaultConfigData.setTransitKeyType(prop.getProperty("vault.transit.keytype"));
            vaultConfigData.setSecretPath(prop.getProperty("vault.secret.path"));
            vaultConfigData.setTlsPemCert(prop.getProperty("vault.tls.server.crt"));
            vaultConfigData.setCreateEncKey(Boolean.getBoolean(prop.getProperty("vault.create.key")));

        } catch (IOException | VaultConfigDataException ex) {
            log.error(ex);
        }
        return vaultConfigData;
    }

    private VaultConfig setVaultConfig(VaultConfigData vaultConfigData) throws VaultException {

        SslConfig sslConfig = new SslConfig();
        sslConfig.verify(vaultConfigData.isVerifySSL());

        if(vaultConfigData.isVerifySSL()){
            if(System.getenv().get("VAULT_SSL_CERT") != null && System.getenv().get("VAULT_SSL_CERT").length()>0) {
                File pemFile = new File(System.getenv().get("VAULT_SSL_CERT"));
                sslConfig.pemFile(pemFile);
                log.debug("VAULT_SSL_CERT variable: " + System.getenv().get("VAULT_SSL_CERT"));
            } else {
                if (vaultConfigData.getTlsPemCert() != null && !vaultConfigData.getTlsPemCert().isEmpty()) {
                    sslConfig.pemUTF8(vaultConfigData.getTlsPemCert());
                }
            }
        }
        return new VaultConfig()
                .address(vaultConfigData.getVaultAddress())            // Defaults to "VAULT_ADDR" environment variable
                .engineVersion(2)
                .token(vaultConfigData.getVaultToken())                // Defaults to "VAULT_TOKEN" environment variable
                .openTimeout(vaultConfigData.getOpenTimeoutSeconds())  // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
                .readTimeout(vaultConfigData.getReadTimeoutSeconds())  // Defaults to "VAULT_READ_TIMEOUT" environment variable
                .sslConfig(sslConfig)
                .build();
    }

    private HealthResponse getHealthResponse() throws VaultException {

        log.debug("Checking Vault Health...");
        return this.vault.debug().health();
    }

    private RestResponse enableTransitEngine() throws VaultMasterKeyEncryptorException {

        String path = "/v1/sys/mounts/transit";

        log.debug("PingFederate will attempt to enable the transit engine. The role will need the correct vault permissions.");

        RestResponse postResponse;
        String payload = Json.object()
                .add("type", "transit")
                .toString();

        try {
            Rest request = new Rest()
                    .url(this.vaultConfigData.getVaultAddress() + path)
                    .header("X-Vault-Token", vaultConfigData.getVaultToken())
                    .body(payload.getBytes(StandardCharsets.UTF_8))
                    .sslVerification(vaultConfigData.isVerifySSL())
                    .connectTimeoutSeconds(vaultConfigData.getOpenTimeoutSeconds())
                    .readTimeoutSeconds(vaultConfigData.getReadTimeoutSeconds());
            VaultResponse vaultResponse = new VaultResponse(request.post(), this.maxRetries);
            postResponse = vaultResponse.getRestResponse();
        } catch(RestException ex){
            throw new VaultMasterKeyEncryptorException("Unable to enable the vault transit engine.", ex);
        }
         return postResponse;
    }

    private boolean isTransitEngineEnabled() {

        boolean enabled = false;

        try {
            MountResponse mountResponse = this.vault.mounts().list();
            JsonObject jsonResponse = mountResponse.getDataObject();
            if(jsonResponse.names().contains("transit/")){
                log.debug("Transit engine is enabled.");
                enabled = true;
            }
            else {
                log.debug("The transit engine is disabled.");
            }

        } catch(VaultException ve){
            log.error(ve);
        }
        return enabled;
    }

    private boolean createTransitKey(String keyName) throws VaultMasterKeyEncryptorException {

        log.debug("Creating the transit encryption key: " + keyName);

        try{
            Map<String, Object> payloadMap = new HashMap<>();
            payloadMap.put("type", vaultConfigData.getTransitKeyType());
            this.vault.logical().write("transit/keys/" + this.keyId, payloadMap);

        } catch(VaultException ve) {
            log.error(ve);
            throw new VaultMasterKeyEncryptorException("Error: Unable to create transit key.", ve);
        }
        return true;
    }

    private void storeKey(String key) throws VaultMasterKeyEncryptorException {

        log.debug("Stored Key payload: "+ key);

        try{
            Map<String, Object> payloadMap = new HashMap<>();
            payloadMap.put("key", key);
            this.vault.logical().write("cubbyhole/" + vaultConfigData.getSecretPath(),payloadMap);
        }
        catch(VaultException ve){
            log.error(ve);
            throw new VaultMasterKeyEncryptorException("Error: storing master key in cubbyhole.", ve);
        }
    }

    private String getTokenFromRoleId(String roleId) throws VaultMasterKeyEncryptorException {

        String payload = Json.object().set("role_id", roleId).toString();
        String vaultToken;

        try {
            Rest request = new Rest()
                    .url(this.vaultConfigData.getVaultAddress() + "/v1/auth/approle/login")
                    .body(payload.getBytes(StandardCharsets.UTF_8))
                    .sslVerification(vaultConfigData.isVerifySSL())
                    .connectTimeoutSeconds(vaultConfigData.getOpenTimeoutSeconds())
                    .readTimeoutSeconds(vaultConfigData.getReadTimeoutSeconds());
            VaultResponse vaultResponse = new VaultResponse(request.post(), this.maxRetries);
            RestResponse response = vaultResponse.getRestResponse();

            if (response.getStatus() >= 200 && response.getStatus() <= 299) {
                String body = new String(response.getBody());
                log.debug("RoleID login response: " + body);
                JsonObject jsonObject = Json.parse(body).asObject();
                vaultToken = jsonObject.get("auth").asObject().get("client_token").asString();
                log.debug("Success! Retrieved client token from role_id: " + roleId+  ".");
                log.debug("Client Token: " + vaultToken);
            } else {
                String errorMsg = new String(response.getBody());
                throw new VaultMasterKeyEncryptorException("Error: Unable to get client token from role_id:" + roleId+  ".); Msg: " + errorMsg);
            }
        } catch(RestException ex){
            throw new VaultMasterKeyEncryptorException("Unable to create the encryption key.", ex);
        }
        return vaultToken;
    }
}
