package com.mobilefund.Exception;

public class InvalidAuthTokenException extends RuntimeException{
    public InvalidAuthTokenException(String msg) {
        super(msg);
    }
}
