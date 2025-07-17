package com.mobilefund.config;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;

public class TwoFactorContext {
    private final String username;
    private final String authToken;
    private final String otp;
    private final LocalDateTime expiryTime;
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final byte[] SERVER_SECRET = "YOUR_SECRET_KEY".getBytes();

    public TwoFactorContext(String username, String passwordHash) {
        this.username = username;
        this.authToken = generateAuthToken(username, passwordHash);
        this.otp = generateRandomOtp();
        this.expiryTime = LocalDateTime.now().plusMinutes(5);
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