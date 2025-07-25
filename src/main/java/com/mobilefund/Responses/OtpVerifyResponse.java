package com.mobilefund.Responses;

public record OtpVerifyResponse(
        boolean success,
        int remainingAttempts,
        long remainingTimeSeconds
) {}
