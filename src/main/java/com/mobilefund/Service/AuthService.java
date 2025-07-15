package com.mobilefund.Service;

import com.mobilefund.Dto.*;
import com.mobilefund.Model.ERole;
import com.mobilefund.Model.OtpCache;
import com.mobilefund.Model.Role;
import com.mobilefund.Model.User;
import com.mobilefund.Repository.OtpCacheRepository;
import com.mobilefund.Repository.RoleRepository;
import com.mobilefund.Repository.UserRepository;
import com.mobilefund.Responses.ApiResponse;
import com.mobilefund.Responses.JwtAuthenticationResponse;
import com.mobilefund.config.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

@Service
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtTokenProvider tokenProvider, SmsService smsService, ExternalValidationService validationService, OtpCacheRepository otpCacheRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenProvider = tokenProvider;
        this.smsService = smsService;
        this.validationService = validationService;
        this.otpCacheRepository = otpCacheRepository;
    }

    private final JwtTokenProvider tokenProvider;
    private final SmsService smsService;
    private final ExternalValidationService validationService;
    private final OtpCacheRepository otpCacheRepository;

    public ResponseEntity<?> authenticateUser(LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            User user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Generate OTP
            String otp = generateOtp();
            LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(5);

            // Save OTP to cache
            otpCacheRepository.save(new OtpCache(
                    user.getPhoneNumber(),
                    otp,
                    expiryTime,
                    "LOGIN",
                    null,
                    user.getNationalCode(),
                    user.getUsername()
            ));

            // Send OTP via SMS
            smsService.sendSms(user.getPhoneNumber(), "Your verification code is: " + otp);

            return ResponseEntity.ok(new ApiResponse(true, "OTP sent to your phone"));
        } catch (AuthenticationException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(false, "Invalid username or password"));
        }
    }

    public ResponseEntity<?> verifyLoginOtp(OtpVerificationRequest otpRequest) {
        Optional<OtpCache> otpCache = otpCacheRepository.findByPhoneNumber(otpRequest.getPhoneNumber());

        if (otpCache.isEmpty() || !otpCache.get().getOperationType().equals("LOGIN")) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP request"));
        }

        if (LocalDateTime.now().isAfter(otpCache.get().getExpiryTime())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "OTP expired"));
        }

        if (!otpCache.get().getOtp().equals(otpRequest.getOtp())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP"));
        }

        // OTP is valid, proceed with login
        User user = userRepository.findByPhoneNumber(otpRequest.getPhoneNumber())
                .orElseThrow(() -> new RuntimeException("User not found"));

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                null
        );

        String jwt = tokenProvider.generateToken(authentication);

        // Clean up OTP cache
        otpCacheRepository.delete(otpCache.get());

        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }

    public ResponseEntity<ApiResponse> registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "Username is already taken!"));
        }

        if (userRepository.existsByPhoneNumber(registerRequest.getPhoneNumber())) {
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "Phone number is already in use!"));
        }

        if (userRepository.existsByNationalCode(registerRequest.getNationalCode())) {
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "National code is already registered!"));
        }

//        // Validate with external service
//        boolean isValid = validationService.validateUser(
//                registerRequest.getNationalCode(),
//                registerRequest.getPhoneNumber()
//        );

        boolean isValid = true;

        if (!isValid) {
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "Validation failed with external service"));
        }

        // Generate OTP
        String otp = generateOtp();
        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(5);

        // Save registration data temporarily with OTP
        otpCacheRepository.save(new OtpCache(
                registerRequest.getPhoneNumber(),
                otp,
                expiryTime,
                "REGISTER",
                passwordEncoder.encode(registerRequest.getPassword()),
                registerRequest.getNationalCode(),
                registerRequest.getUsername()
        ));

        // Send OTP via SMS
        smsService.sendSms(registerRequest.getPhoneNumber(), "Your verification code is: " + otp);

        return ResponseEntity.ok(new ApiResponse(true, "OTP sent to your phone for registration"));
    }

    public ResponseEntity<?> verifyRegistrationOtp(OtpVerificationRequest otpRequest) {
        Optional<OtpCache> otpCache = otpCacheRepository.findByPhoneNumber(otpRequest.getPhoneNumber());

        if (otpCache.isEmpty() || !otpCache.get().getOperationType().equals("REGISTER")) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP request"));
        }

        if (LocalDateTime.now().isAfter(otpCache.get().getExpiryTime())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "OTP expired"));
        }

        if (!otpCache.get().getOtp().equals(otpRequest.getOtp())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP"));
        }

        // Retrieve registration data from temporary storage
//        String[] storedData = otpCache.get().getTempData().split(";;");
//        if (storedData.length != 4) {
//            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid registration data"));
//        }

        // Reconstruct RegisterRequest
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setNationalCode(otpCache.get().getNationalCode());
        registerRequest.setUsername(otpCache.get().getUsername());
        registerRequest.setPassword(otpCache.get().getTempData()); // This is already encoded
        registerRequest.setPhoneNumber(otpRequest.getPhoneNumber());

        // Create user
        User user = new User(
                registerRequest.getNationalCode(),
                registerRequest.getUsername(),
                registerRequest.getPassword(), // Already encoded password
                registerRequest.getPhoneNumber()
        );

        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow();
        roles.add(userRole);

        user.setRoles(roles);
        userRepository.save(user);

        // Clean up OTP cache
        otpCacheRepository.delete(otpCache.get());

        return ResponseEntity.ok(new ApiResponse(true, "User registered successfully!"));
    }

    public ResponseEntity<?> forgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        User user = userRepository.findByUsername(forgotPasswordRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate with external service
        boolean isValid = validationService.validateUser(
                user.getNationalCode(),
                user.getPhoneNumber()
        );

        if (!isValid) {
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "Validation failed with external service"));
        }

        // Generate OTP
        String otp = generateOtp();
        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(5);

        // Save OTP to cache
        otpCacheRepository.save(new OtpCache(
                user.getPhoneNumber(),
                otp,
                expiryTime,
                "RESET_PASSWORD",
                null,
                user.getNationalCode(),
                user.getUsername()
        ));

        // Send OTP via SMS
        smsService.sendSms(user.getPhoneNumber(), "Your password reset code is: " + otp);

        return ResponseEntity.ok(new ApiResponse(true, "OTP sent to your phone for password reset"));
    }

    public ResponseEntity<?> resetPassword(ResetPasswordRequest resetPasswordRequest) {
        Optional<OtpCache> otpCache = otpCacheRepository.findById(Integer.valueOf(resetPasswordRequest.getPhoneNumber()));

        if (otpCache.isEmpty() || !otpCache.get().getOperationType().equals("RESET_PASSWORD")) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP request"));
        }

        if (LocalDateTime.now().isAfter(otpCache.get().getExpiryTime())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "OTP expired"));
        }

        if (!otpCache.get().getOtp().equals(resetPasswordRequest.getOtp())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP"));
        }

        // Update password
        User user = userRepository.findByPhoneNumber(resetPasswordRequest.getPhoneNumber())
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(passwordEncoder.encode(resetPasswordRequest.getNewPassword()));
        userRepository.save(user);

        // Clean up OTP cache
        otpCacheRepository.delete(otpCache.get());

        return ResponseEntity.ok(new ApiResponse(true, "Password updated successfully!"));
    }

    private String generateOtp() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    public Boolean validateToken(String token) {
        return tokenProvider.validateToken(token);
    }
}
