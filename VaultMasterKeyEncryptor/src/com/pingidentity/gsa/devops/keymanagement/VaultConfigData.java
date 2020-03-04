package com.pingidentity.gsa.devops.keymanagement;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.VaultConfig;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;

public class VaultConfigData {

    private String vaultAddress;
    private String vaultToken;
    private String vaultRoleId;
    private boolean verifySSL = true;
    private int maxRetry = 3;
    private int retryIntervalMilliseconds = 3000;
    private int openTimeoutSeconds = 3;
    private int readTimeoutSeconds = 3;
    private String transitKeyType = "aes256-gcm96";
    private String[] supportTransitKeyTypes = new String[] {"aes128-gcm96", "aes256-gcm96", "rsa-2048", "rsa-4096"};
    private String secretPath = "";
    private String transitKeyName = "pingfederate";
    private String tlsPemCert = "";
    private VaultConfig vaultConfig;
    private boolean createEncKey = false;

    private final Log log = LogFactory.getLog(this.getClass());

    public String getVaultAddress() {
        return vaultAddress;
    }

    public void setVaultAddress(String vaultAddress) {
        this.vaultAddress = vaultAddress;
    }

    public String getVaultToken() {
        return vaultToken;
    }

    public void setVaultToken(String vaultToken) {
        this.vaultToken = vaultToken;
    }

    public boolean isVerifySSL() {
        return verifySSL;
    }

    public void setVerifySSL(boolean verifySSL) {
        this.verifySSL = verifySSL;
    }

    public int getMaxRetry() {
        return maxRetry;
    }

    public void setMaxRetry(int maxRetry) {
        this.maxRetry = maxRetry;
    }

    public int getRetryIntervalMilliseconds() {
        return retryIntervalMilliseconds;
    }

    public void setRetryIntervalMilliseconds(int retryIntervalMilliseconds) {
        this.retryIntervalMilliseconds = retryIntervalMilliseconds;
    }

    public int getOpenTimeoutSeconds() {
        return openTimeoutSeconds;
    }

    public void setOpenTimeoutSeconds(int openTimeoutSeconds) {
        this.openTimeoutSeconds = openTimeoutSeconds;
    }

    public int getReadTimeoutSeconds() {
        return readTimeoutSeconds;
    }

    public void setReadTimeoutSeconds(int readTimeoutSeconds) {
        this.readTimeoutSeconds = readTimeoutSeconds;
    }

    public String getTransitKeyType() {
        return transitKeyType;
    }

    public void setTransitKeyType(String transitKeyType) throws VaultConfigDataException {
        if(isTransitKeyTypeSupported(transitKeyType)) {
            this.transitKeyType = transitKeyType;
        }  else {
            throw new VaultConfigDataException("Key type: " + transitKeyType + " is not supported. Setting to default: " + this.transitKeyType);

        }
    }

    private boolean isTransitKeyTypeSupported(String transitKeyType){

        return Arrays.asList(supportTransitKeyTypes).contains(transitKeyType);
    }

    public String getSecretPath() {
        return secretPath;
    }

    public void setSecretPath(String secretPath) {

        if(secretPath == null || secretPath.isEmpty()){
            this.secretPath = "/dev/ping/master";
        } else {
            this.secretPath = secretPath;
        }
    }

    public String getVaultRoleId() {
        return vaultRoleId;
    }

    public void setVaultRoleId(String vaultRoleId) {
        this.vaultRoleId = vaultRoleId;
    }

    public String getTransitKeyName() {
        return transitKeyName;
    }

    public void setTransitKeyName(String transitKeyName) {
        this.transitKeyName = transitKeyName;
    }

    public String getTlsPemCert() {
        return tlsPemCert;
    }

    public void setTlsPemCert(String tlsPemCert) {
        this.tlsPemCert = tlsPemCert;
    }

    public VaultConfig getVaultConfig() {
        return vaultConfig;
    }

    public void setVaultConfig(VaultConfig vaultConfig) {
        this.vaultConfig = vaultConfig;
    }

    public SslConfig getSslConfig(){
        return this.vaultConfig.getSslConfig();
    }

    public boolean isCreateEncKey() {
        return createEncKey;
    }

    public void setCreateEncKey(boolean createKey) {
        this.createEncKey = createKey;
    }
}
