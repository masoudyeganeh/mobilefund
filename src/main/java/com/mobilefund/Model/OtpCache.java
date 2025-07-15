package com.mobilefund.Model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
public class OtpCache {
    @Id
    private String phoneNumber;

    public OtpCache() {

    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(LocalDateTime expiryTime) {
        this.expiryTime = expiryTime;
    }

    public String getOperationType() {
        return operationType;
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    public String getTempData() {
        return tempData;
    }

    public void setTempData(String tempData) {
        this.tempData = tempData;
    }

    public String getNationalCode() {
        return nationalCode;
    }

    public void setNationalCode(String nationalCode) {
        this.nationalCode = nationalCode;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    private String otp;
    private LocalDateTime expiryTime;
    private String operationType; // "REGISTER", "LOGIN", "RESET_PASSWORD"
    private String tempData; // Store temporary data like password for registration
    private String nationalCode;
    private String username;

    public OtpCache(String phoneNumber, String otp, LocalDateTime expiryTime, String operationType, String tempData, String nationalCode, String username) {
        this.phoneNumber = phoneNumber;
        this.otp = otp;
        this.expiryTime = expiryTime;
        this.operationType = operationType;
        this.tempData = tempData;
        this.nationalCode = nationalCode;
        this.username = username;
    }
}