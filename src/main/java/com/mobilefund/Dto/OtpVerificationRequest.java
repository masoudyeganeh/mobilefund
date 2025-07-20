package com.mobilefund.Dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class OtpVerificationRequest {
    @NotBlank
    private String phoneNumber;

    public String getOtp() {
        return otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    @NotNull @NotBlank
    private String otp;
}