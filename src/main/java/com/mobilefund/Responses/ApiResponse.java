package com.mobilefund.Responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class ApiResponse {
    private Boolean success;
    private String message;

    public ApiResponse(Boolean success, String message) {}
}
