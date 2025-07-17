package com.mobilefund.Responses;

public record FirstFactorResponse(
        boolean success,
        String message,
        String authToken
) {}
