package com.mobilefund.config;

import java.io.Serializable;
import java.time.LocalDateTime;

public class OtpContext implements Serializable {
    private String otp;
    private int attempts;
    private LocalDateTime issuedAt;

    public OtpContext() {}

    public OtpContext(String otp, int attempts, LocalDateTime issuedAt) {
        this.otp = otp;
        this.attempts = attempts;
        this.issuedAt = issuedAt;
    }

    public String getOtp() {
        return otp;
    }

    public OtpContext setOtp(String otp) {
        this.otp = otp;
        return this;
    }

    public int getAttempts() {
        return attempts;
    }

    public OtpContext setAttempts(int attempts) {
        this.attempts = attempts;
        return this;
    }

    public LocalDateTime getIssuedAt() {
        return issuedAt;
    }

    public OtpContext setIssuedAt(LocalDateTime issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }
}
