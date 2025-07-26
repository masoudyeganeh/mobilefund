package com.mobilefund.Redis.Config.Repository;

import com.mobilefund.config.OtpContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Repository
public class RedisAuthRepository {

    private final RedisTemplate<String, String> jwtRedisTemplate;
    private final RedisTemplate<String, OtpContext> otpTemplate;

    @Autowired
    public RedisAuthRepository(RedisTemplate<String, String> jwtRedisTemplate,
                               RedisTemplate<String, OtpContext> otpTemplate) {
        this.jwtRedisTemplate = jwtRedisTemplate;
        this.otpTemplate = otpTemplate;
    }

    // JWT Token Handling
    public void saveJwtToken(String username, String jwt, long minutes) {
        jwtRedisTemplate.opsForValue().set("jwt:" + username, jwt, minutes, TimeUnit.MINUTES);
    }

    public String getJwtToken(String username) {
        return jwtRedisTemplate.opsForValue().get("jwt:" + username);
    }

    public void deleteJwtToken(String username) {
        jwtRedisTemplate.delete("jwt:" + username);
    }

    // OTP Context Handling
    public void saveOtpContext(String context, String phoneNumber, OtpContext otpContext, long ttlMinutes) {
        otpTemplate.opsForValue().set("otp:" + context + ":" + phoneNumber, otpContext, ttlMinutes, TimeUnit.MINUTES);
    }

    public Optional<OtpContext> getOtpContext(String context, String phoneNumber) {
        OtpContext ctx = otpTemplate.opsForValue().get("otp:" + context + ":" + phoneNumber);
        return Optional.ofNullable(ctx);
    }

    public void deleteOtpContext(String context, String phoneNumber) {
        otpTemplate.delete("otp:" + context + ":" + phoneNumber);
    }

    // Rate Limiting (e.g., 5 OTP requests per 10 minutes)
    public boolean incrementOtpRequestCount(String phoneNumber, int maxRequests, long windowMinutes) {
        String key = "rate:otp:" + phoneNumber;
        Long count = jwtRedisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            jwtRedisTemplate.expire(key, windowMinutes, TimeUnit.MINUTES);
        }
        return count <= maxRequests;
    }
}

