package com.mobilefund.Redis.Config.Repository;

import com.mobilefund.config.TwoFactorContext;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Component
public class TwoFactorRepository {
    private final RedisTemplate<String, TwoFactorContext> redisTemplate;
    private static final String KEY_PREFIX = "2fa:";

    public TwoFactorRepository(RedisTemplate<String, TwoFactorContext> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void save(TwoFactorContext twoFactorContext, Duration ttl){
        twoFactorContext.setExpiryTime(Instant.now().plus(ttl));
        redisTemplate.opsForValue().set(
                KEY_PREFIX + twoFactorContext.getPhoneNumber(),
                twoFactorContext,
                ttl
        );
    }

    public Optional<TwoFactorContext> findByPhoneNumber(String phoneNumber) {
        return Optional.ofNullable(
                redisTemplate.opsForValue().get(KEY_PREFIX + phoneNumber)
        );
    }

    public void delete(String phoneNumber) {
        redisTemplate.delete(KEY_PREFIX + phoneNumber);
    }
}
