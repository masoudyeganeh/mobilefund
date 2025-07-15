package com.mobilefund.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class ExternalValidationService {

    @Value("${external.validation.url}")
    private String validationUrl;

    private final RestTemplate restTemplate;

    public ExternalValidationService(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    public boolean validateUser(String nationalCode, String phoneNumber) {
        try {
            // Prepare request
            Map<String, String> request = new HashMap<>();
            request.put("national_code", nationalCode);
            request.put("phone_number", phoneNumber);

            // Call external service
            ResponseEntity<Boolean> response = restTemplate.postForEntity(
                    validationUrl,
                    request,
                    Boolean.class
            );

            return Boolean.TRUE.equals(response.getBody());
        } catch (Exception e) {
            // Log error
            return false;
        }
    }
}
