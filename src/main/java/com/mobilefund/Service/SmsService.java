package com.mobilefund.Service;

import com.mobilefund.Exception.OtpCodeIsNotSent;
import com.mobilefund.Redis.Config.Repository.TwoFactorRepository;
import com.mobilefund.Responses.OtpSendResponse;
import com.mobilefund.Responses.OtpVerifyResponse;
import com.mobilefund.config.JwtTokenProvider;
import com.mobilefund.config.TwoFactorContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
public class SmsService {

    @Value("${sms.provider.url}")
    private String smsProviderUrl;

    @Value("${sms.provider.apiKey}")
    private String apiKey;

    @Value("${sms.validity.minutes}")
    private int otpValidityMinutes;

    @Value("${sms.max.attempts}")
    private int maxAttempts;

    private final RestTemplate restTemplate;

    private final TwoFactorRepository twoFactorRepo;
    private final JwtTokenProvider jwtTokenProvider;

    public SmsService(RestTemplateBuilder restTemplateBuilder, TwoFactorRepository twoFactorRepo, JwtTokenProvider jwtTokenProvider) {
        this.restTemplate = restTemplateBuilder.build();
        this.twoFactorRepo = twoFactorRepo;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public void sendSms(String phoneNumber, String message) {

            // Prepare request
            Map<String, String> request = new HashMap<>();
            request.put("to", phoneNumber);
            request.put("message", message);
            request.put("api_key", apiKey);

            System.out.println(message);
    }
}
