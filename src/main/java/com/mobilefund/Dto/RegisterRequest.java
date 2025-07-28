package com.mobilefund.Dto;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    @NotBlank
    private String nationalCode;

    @NotBlank
    private String phoneNumber;

    public String getNationalCode() {
        return nationalCode;
    }

    public RegisterRequest setNationalCode(String nationalCode) {
        this.nationalCode = nationalCode;
        return this;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public RegisterRequest setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }
}
