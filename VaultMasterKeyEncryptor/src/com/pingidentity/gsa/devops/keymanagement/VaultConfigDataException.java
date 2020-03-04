package com.pingidentity.gsa.devops.keymanagement;

public class VaultConfigDataException extends Exception {


    VaultConfigDataException(String message){
        super(message);
    }

    VaultConfigDataException(String message, Throwable cause){
        super(message,cause);
    }

}
