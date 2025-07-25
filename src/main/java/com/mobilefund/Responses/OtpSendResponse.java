package com.mobilefund.Responses;

public record OtpSendResponse(
        long remainingTimeSeconds,
        int remainingAttempts
) {
}
