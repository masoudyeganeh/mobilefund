package com.mobilefund.Controller;

import com.mobilefund.Dto.*;
import com.mobilefund.Responses.ApiResponse;
import com.mobilefund.Responses.FirstFactorResponse;
import com.mobilefund.Responses.JwtAuthenticationResponse;
import com.mobilefund.Service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<FirstFactorResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            return authService.authenticateUser(loginRequest);
        } catch (AuthenticationException e) {
        throw e;
        }
    }

    @PostMapping("/login/verify")
    public ResponseEntity<JwtAuthenticationResponse> verifyLoginOtp(@Valid @RequestBody OtpVerificationRequest otpRequest,
                                                                    @RequestHeader("X-AUTH-TOKEN") String authToken
    ) {
        return authService.verifyLoginOtp(otpRequest, authToken);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        return authService.registerUser(registerRequest);
    }

    @PostMapping("/register/verify")
    public ResponseEntity<?> verifyRegistrationOtp(@Valid @RequestBody OtpVerificationRequest otpRequest) {
        return authService.verifyRegistrationOtp(otpRequest);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest) {
        return authService.forgotPassword(forgotPasswordRequest);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        return authService.resetPassword(resetPasswordRequest);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        // In JWT, logout is handled client-side by discarding the token
        return ResponseEntity.ok(new ApiResponse(true, "Logout successful"));
    }

    @GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            if (authService.validateToken(token)) {
                return ResponseEntity.ok(new ApiResponse(true, "Token is valid"));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse(false, "Token is invalid"));
    }
}
