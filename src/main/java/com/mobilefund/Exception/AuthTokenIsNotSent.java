package com.mobilefund.Exception;

public class AuthTokenIsNotSent extends RuntimeException {
    public AuthTokenIsNotSent(String msg) {
        super(msg);
    }
}
