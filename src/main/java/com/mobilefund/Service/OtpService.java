package com.mobilefund.Service;

import com.mobilefund.Redis.Config.Repository.RedisAuthRepository;
import com.mobilefund.config.OtpContext;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

@Service
public class OtpService {

    private final RedisAuthRepository redisRepo;

    public OtpService(RedisAuthRepository redisRepo) {
        this.redisRepo = redisRepo;
    }

    public boolean requestOtp(String context, String phoneNumber) {
        int maxRequests = 5;
        long rateLimitWindowMinutes = 10;

        if (!redisRepo.incrementOtpRequestCount(phoneNumber, maxRequests, rateLimitWindowMinutes)) {
            throw new RuntimeException("Too many OTP requests. Please wait.");
        }

        String generatedOtp = generateOtp();
        OtpContext otpContext = new OtpContext(generatedOtp, 0, LocalDateTime.now());

        redisRepo.saveOtpContext(context, phoneNumber, otpContext, 2);
        return true;
    }

    public boolean verifyOtp(String context, String phoneNumber, String submittedOtp) {
        Optional<OtpContext> ctxOpt = redisRepo.getOtpContext(context, phoneNumber);
        if (ctxOpt.isEmpty()) {
            throw new RuntimeException("OTP expired or not found.");
        }

        OtpContext ctx = ctxOpt.get();

        if (ctx.getAttempts() >= 3) {
            redisRepo.deleteOtpContext(context, phoneNumber);
            throw new RuntimeException("Maximum OTP attempts exceeded.");
        }

        if (ctx.getOtp().equals(submittedOtp)) {
            redisRepo.deleteOtpContext(context, phoneNumber); // One-time use
            return true;
        } else {
            ctx.setAttempts(ctx.getAttempts() + 1);
            redisRepo.saveOtpContext(context, phoneNumber, ctx, 2);
            return false;
        }
    }

    private String generateOtp() {
        return String.valueOf(ThreadLocalRandom.current().nextInt(100000, 999999));
    }
}
