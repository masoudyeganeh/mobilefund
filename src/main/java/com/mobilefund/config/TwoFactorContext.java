package com.mobilefund.config;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.io.Serializable;
import java.time.Instant;

public class TwoFactorContext implements Serializable {
    private String nationalCode;
    private String otp;
    private String phoneNumber;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private Instant expiryTime = Instant.now().plusSeconds(600); // 10 minutes expiry

    // Constructors
    public TwoFactorContext() {}

    public TwoFactorContext(String nationalCode, String password, String phoneNumber) {
        this.nationalCode = nationalCode;
        this.phoneNumber = phoneNumber;
        this.otp = generateRandomOtp();
    }

    // Business logic methods
    @JsonIgnore
    public boolean isExpired() {
        return Instant.now().isAfter(expiryTime);
    }

    private String generateRandomOtp() {
        return String.format("%06d", (int)(Math.random() * 1000000));
    }

    // Getters and Setters
    public String getNationalCode() { return nationalCode; }
    public void setNationalCode(String nationalCode) { this.nationalCode = nationalCode; }
    public String getOtp() { return otp; }
    public void setOtp(String otp) { this.otp = otp; }
    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
    public Instant getExpiryTime() { return expiryTime; }
    public void setExpiryTime(Instant expiryTime) { this.expiryTime = expiryTime; }
}