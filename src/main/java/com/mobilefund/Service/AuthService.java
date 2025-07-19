package com.mobilefund.Service;

import com.mobilefund.Dto.*;
import com.mobilefund.Exception.ExpiredAuthTokenException;
import com.mobilefund.Exception.InvalidAuthTokenException;
import com.mobilefund.Exception.InvalidOtpException;
import com.mobilefund.Model.*;
import com.mobilefund.Redis.Config.Repository.TwoFactorRepository;
import com.mobilefund.Repository.OtpCacheRepository;
import com.mobilefund.Repository.RoleRepository;
import com.mobilefund.Repository.UserRepository;
import com.mobilefund.Responses.ApiResponse;
import com.mobilefund.Responses.FirstFactorResponse;
import com.mobilefund.Responses.JwtAuthenticationResponse;
import com.mobilefund.config.AuthCache;
import com.mobilefund.config.CustomUserDetailsService;
import com.mobilefund.config.JwtTokenProvider;
import com.mobilefund.config.TwoFactorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
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
    private final AuthCache authCache;
    private final CustomUserDetailsService customUserDetailsService;
    private final TwoFactorRepository twoFactorRepository;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, AuthCache authCache, CustomUserDetailsService customUserDetailsService, TwoFactorRepository twoFactorRepository, JwtTokenProvider tokenProvider, SmsService smsService, ExternalValidationService validationService, OtpCacheRepository otpCacheRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authCache = authCache;
        this.customUserDetailsService = customUserDetailsService;
        this.twoFactorRepository = twoFactorRepository;
        this.tokenProvider = tokenProvider;
        this.smsService = smsService;
        this.validationService = validationService;
        this.otpCacheRepository = otpCacheRepository;

    }

    private final JwtTokenProvider tokenProvider;
    private final SmsService smsService;
    private final ExternalValidationService validationService;
    private final OtpCacheRepository otpCacheRepository;

    public ResponseEntity<FirstFactorResponse> authenticateUser(LoginRequest loginRequest) {

            User user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid credentials");
            }

            TwoFactorContext context = new TwoFactorContext(
                    loginRequest.getUsername(),
                    user.getPassword(),
                    user.getPhoneNumber()
            );

            twoFactorRepository.save(context, Duration.ofMinutes(10));
            smsService.sendSms(user.getPhoneNumber(), "Your OTP: " + context.getOtp());

        return ResponseEntity.ok(
                new FirstFactorResponse(true, "OTP sent", context.getAuthToken())
        );
    }

    public ResponseEntity<JwtAuthenticationResponse> verifyLoginOtp(OtpVerificationRequest otpRequest, String authToken) {

        TwoFactorContext context = twoFactorRepository.findByAuthToken(authToken)
                .orElseThrow(() -> new InvalidAuthTokenException("Invalid authentication token"));

        if (context.isExpired()) {
            twoFactorRepository.delete(authToken);
            throw new ExpiredAuthTokenException("Authentication token expired");
        }

        if (!context.getOtp().equals(otpRequest.getOtp())) {
            throw new InvalidOtpException("Invalid OTP code");
        }

        twoFactorRepository.delete(authToken);

        UserPrincipal principal = (UserPrincipal) customUserDetailsService.loadUserByUsername(
                context.getUsername()
        );

        String jwt = tokenProvider.generateToken(
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        principal.getAuthorities()
                )
        );

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
