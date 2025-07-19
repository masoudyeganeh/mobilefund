package com.mobilefund.Exception;

public class ExpiredAuthTokenException extends RuntimeException {
    public ExpiredAuthTokenException(String msg) {
        super(msg);
    }
}
