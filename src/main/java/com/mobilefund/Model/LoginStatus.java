package com.mobilefund.Model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum LoginStatus {
    SUCCESS("SUCCESS"),
    OTP_REQUIRED("OTP_REQUIRED"),
    OTP_INVALID("OTP_INVALID"),
    OTP_EXPIRED("OTP_EXPIRED"),
    INVALID_CREDENTIALS("INVALID_CREDENTIALS");

    private final String value;

    LoginStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
