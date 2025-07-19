package com.mobilefund.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;

@JsonSerialize
@JsonDeserialize
@AllArgsConstructor
@NoArgsConstructor
public class TwoFactorContext implements Serializable {
    private String username;
    private String authToken;
    private String otp;
    private String phoneNumber;
    private LocalDateTime expiryTime;
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final byte[] SERVER_SECRET = "YOUR_SECRET_KEY".getBytes();

    @JsonIgnore
    public boolean isExpired() {
        return expiryTime.plusMinutes(5).isBefore(LocalDateTime.now());
    }

    public TwoFactorContext(String username, String passwordHash, String phoneNumber) {
        this.username = username;
        this.authToken = generateAuthToken(username, passwordHash);
        this.otp = generateRandomOtp();
        this.phoneNumber = phoneNumber;
        this.expiryTime = LocalDateTime.now().plusMinutes(10);
    }

    public TwoFactorContext(LocalDateTime expiryTime, String phoneNumber, String otp, String authToken, String username) {
        this.expiryTime = expiryTime;
        this.phoneNumber = phoneNumber;
        this.otp = otp;
        this.authToken = authToken;
        this.username = username;
    }

    private String generateAuthToken(String username, String passwordHash) {
        try {
            Mac hmac = Mac.getInstance(HMAC_ALGO);
            hmac.init(new SecretKeySpec(SERVER_SECRET, HMAC_ALGO));
            String data = username + System.currentTimeMillis() + passwordHash;
            byte[] hash = hmac.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to generate auth token", e);
        }
    }

    public boolean validate(String inputAuthToken, String inputOtp) {
        return this.authToken.equals(inputAuthToken) &&
                this.otp.equals(inputOtp) &&
                LocalDateTime.now().isBefore(expiryTime);
    }

    public String getAuthToken() { return authToken; }
    public String getOtp() { return otp; }
    public String getUsername() { return username; }

    private String generateRandomOtp() {
        return String.format("%06d", (int)(Math.random() * 1000000));
    }
}