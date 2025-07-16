package com.mobilefund.Responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class JwtAuthenticationResponse {
    private String accessToken;

    // Constructor with accessToken parameter
    public JwtAuthenticationResponse(String accessToken) {
        this.accessToken = accessToken;
    }

    // Default constructor (if needed for frameworks)
    public JwtAuthenticationResponse() {
    }

    public JwtAuthenticationResponse(UsernamePasswordAuthenticationToken auth) {
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}
