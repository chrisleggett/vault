package com.pingidentity.gsa.devops.keymanagement;

import com.pingidentity.sdk.key.MasterKeyEncryptorException;

public class VaultMasterKeyEncryptorException extends MasterKeyEncryptorException {

    VaultMasterKeyEncryptorException(String message){
        super(message);
    }

    VaultMasterKeyEncryptorException(String message, Throwable cause){
        super(message,cause);
    }

}
