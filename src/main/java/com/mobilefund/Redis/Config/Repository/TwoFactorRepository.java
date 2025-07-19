package com.mobilefund.Redis.Config.Repository;

import com.mobilefund.config.TwoFactorContext;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
public class TwoFactorRepository {
    private final RedisTemplate<String, TwoFactorContext> redisTemplate;
    private static final String KEY_PREFIX = "2fa:";

    public TwoFactorRepository(RedisTemplate<String, TwoFactorContext> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void save(TwoFactorContext twoFactorContext, Duration ttl){
        redisTemplate.opsForValue().set(
                KEY_PREFIX + twoFactorContext.getAuthToken(),
                twoFactorContext,
                ttl
        );
    }

    public Optional<TwoFactorContext> findByAuthToken(String authToken) {
        return Optional.ofNullable(
                redisTemplate.opsForValue().get(KEY_PREFIX + authToken)
        );
    }

    public void delete(String authToken) {
        redisTemplate.delete(KEY_PREFIX + authToken);
    }
}
