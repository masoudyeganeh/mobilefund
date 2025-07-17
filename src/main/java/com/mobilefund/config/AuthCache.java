package com.mobilefund.config;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AuthCache {
    private final ConcurrentHashMap<String, TwoFactorContext> contexts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> otpToUsername = new ConcurrentHashMap<>();

    public void store(TwoFactorContext context) {
        contexts.put(context.getUsername(), context);
        otpToUsername.put(context.getOtp(), context.getUsername());
    }

    public Optional<TwoFactorContext> findByOtp(String otp) {
        return Optional.ofNullable(otpToUsername.get(otp))
                .map(contexts::get);
    }

    public void invalidate(String username) {
        TwoFactorContext context = contexts.remove(username);
        if (context != null) {
            otpToUsername.remove(context.getOtp());
        }
    }
}