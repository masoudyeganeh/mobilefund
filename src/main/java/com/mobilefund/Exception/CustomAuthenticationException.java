package com.mobilefund.Exception;

public class CustomAuthenticationException extends RuntimeException {
    public CustomAuthenticationException(String msg) {
        super(msg);
    }
}
