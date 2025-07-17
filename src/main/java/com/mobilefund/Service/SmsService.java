package com.mobilefund.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class SmsService {

    @Value("${sms.provider.url}")
    private String smsProviderUrl;

    @Value("${sms.provider.apiKey}")
    private String apiKey;

    private final RestTemplate restTemplate;

    public SmsService(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    public void sendSms(String phoneNumber, String message) {
        try {
            // Prepare request
            Map<String, String> request = new HashMap<>();
            request.put("to", phoneNumber);
            request.put("message", message);
            request.put("api_key", apiKey);

            System.out.println(message);

        } catch (Exception e) {
        }
    }
}
