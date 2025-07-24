package com.mobilefund.Controller;

import com.mobilefund.Dto.*;
import com.mobilefund.Responses.ApiResponse;
import com.mobilefund.Responses.FirstFactorResponse;
import com.mobilefund.Responses.JwtAuthenticationResponse;
import com.mobilefund.Responses.LoginResponse;
import com.mobilefund.Service.AuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.time.Duration;
import java.util.Objects;

@RestController
@RequestMapping("/api/v1")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        try {
            LoginResponse loginResponse = authService.authenticateUser(loginRequest);
            if (!Objects.equals(loginResponse.getJwt(), "otp required")) {
                ResponseCookie cookie = ResponseCookie.from("jwt", loginResponse.getJwt())
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(Duration.ofDays(30))
                        .sameSite("Strict")
                        .domain("yourdomain.com")
                        .build();
                response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
                return ResponseEntity.ok(
                        loginResponse);
            }
            return ResponseEntity.ok(
                    loginResponse);
        } catch (AuthenticationException e) {
        throw e;
        }
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
