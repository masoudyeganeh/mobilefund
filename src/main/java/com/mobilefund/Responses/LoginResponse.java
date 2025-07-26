package com.mobilefund.Responses;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.mobilefund.Model.LoginStatus;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {
    private LoginStatus loginStatus;
    private String remainingTime;
    private String remainingAttempts;
    private String nationalCode;
    private String mobileNumber;
    @JsonIgnore
    private String jwt;

    public LoginResponse(LoginStatus loginStatus, String remainingTime, String remainingAttempts, String nationalCode, String mobileNumber, String jwt) {
        this.loginStatus = loginStatus;
        this.remainingTime = remainingTime;
        this.remainingAttempts = remainingAttempts;
        this.nationalCode = nationalCode;
        this.mobileNumber = mobileNumber;
        this.jwt = jwt;
    }

    public LoginResponse() {}

    public LoginStatus getLoginStatus() {
        return loginStatus;
    }

    public LoginResponse setLoginStatus(LoginStatus loginStatus) {
        this.loginStatus = loginStatus;
        return this;
    }

    public String getRemainingTime() {
        return remainingTime;
    }

    public LoginResponse setRemainingTime(String remainingTime) {
        this.remainingTime = remainingTime;
        return this;
    }

    public String getRemainingAttempts() {
        return remainingAttempts;
    }

    public LoginResponse setRemainingAttempts(String remainingAttempts) {
        this.remainingAttempts = remainingAttempts;
        return this;
    }

    public String getNationalCode() {
        return nationalCode;
    }

    public LoginResponse setNationalCode(String nationalCode) {
        this.nationalCode = nationalCode;
        return this;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public LoginResponse setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
        return this;
    }

    public String getJwt() {
        return jwt;
    }

    public LoginResponse setJwt(String jwt) {
        this.jwt = jwt;
        return this;
    }
}
