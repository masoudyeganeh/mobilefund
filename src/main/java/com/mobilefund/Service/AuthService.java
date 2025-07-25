package com.mobilefund.Service;

import com.mobilefund.Dto.*;
import com.mobilefund.Exception.*;
import com.mobilefund.Model.*;
import com.mobilefund.Redis.Config.Repository.TwoFactorRepository;
import com.mobilefund.Repository.OtpCacheRepository;
import com.mobilefund.Repository.RoleRepository;
import com.mobilefund.Repository.UserRepository;
import com.mobilefund.Responses.ApiResponse;
import com.mobilefund.Responses.JwtAuthenticationResponse;
import com.mobilefund.Responses.LoginResponse;
import com.mobilefund.Responses.OtpVerifyResponse;
import com.mobilefund.config.CustomUserDetailsService;
import com.mobilefund.config.JwtTokenProvider;
import com.mobilefund.config.TwoFactorContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
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
    private final CustomUserDetailsService customUserDetailsService;
    private final TwoFactorRepository twoFactorRepository;

    @Value("${sms.validity.minutes}")
    private int otpValidityMinutes;

    @Value("${sms.max.attempts}")
    private int maxAttempts;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, CustomUserDetailsService customUserDetailsService, TwoFactorRepository twoFactorRepository, JwtTokenProvider tokenProvider, SmsService smsService, ExternalValidationService validationService, OtpCacheRepository otpCacheRepository) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
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

    public User findUserByUsername(String username) throws UserNotFoundException {
        Optional<User> user = userRepository.findByNationalCode(username);
        if (user.isPresent()) {
            return user.get();
        }

        user = Optional.ofNullable(userRepository.findByPhoneNumber(username));
        if (user.isPresent()) {
            return user.get();
        }

        throw new UserNotFoundException("User not found");
    }

    public OtpVerifyResponse verifyOtp(TwoFactorContext context, String otp) {
        if (context.isExpired()) {
            twoFactorRepository.delete(context.getPhoneNumber());
            throw new OtpCodeIsNotSent("OTP expired");
        }

        if (!context.getOtp().equals(otp)) {
            context.setRemainingAttempts(context.getRemainingAttempts() - 1);
            twoFactorRepository.save(context);

            if (context.getRemainingAttempts() <= 0) {
                twoFactorRepository.delete(context.getPhoneNumber());
                throw new OtpCodeIsNotSent("Max attempts reached");
            }

            return new OtpVerifyResponse(
                    false,
                    context.getRemainingAttempts(),
                    context.getRemainingTime().getSeconds()
            );
        }

            // Successful verification
            twoFactorRepository.delete(context.getPhoneNumber());
//        String jwtToken = jwtTokenUtil.generateToken(phoneNumber);

            return new OtpVerifyResponse(
                    true,
                    context.getRemainingAttempts(),
                    context.getRemainingTime().getSeconds()
            );
    }

    public LoginResponse authenticateUser(LoginRequest loginRequest) {

        User user = findUserByUsername(loginRequest.getUsername());

        Optional<TwoFactorContext> context = twoFactorRepository.findByPhoneNumber(user.getPhoneNumber());

        if (loginRequest.getOtp() == null && user.isTwoFactorAuth() && !context.isPresent()) {
            TwoFactorContext contextGenerated = new TwoFactorContext(
                    user.getNationalCode(),
                    user.getPhoneNumber(),
                    Instant.now().plusSeconds(otpValidityMinutes * 60L),
                    maxAttempts
            );
            twoFactorRepository.save(contextGenerated);
            smsService.sendSms(user.getPhoneNumber(), "Your OTP: " + contextGenerated.getOtp());
            return new LoginResponse()
                    .setLoginStatus("otp required")
                    .setRemainingTime(String.valueOf(otpValidityMinutes))
                    .setRemainingAttempts(String.valueOf(maxAttempts));
        }

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        if (context.isPresent() && user.isTwoFactorAuth()) {
            if (loginRequest.getOtp() == null || loginRequest.getOtp().isEmpty() || loginRequest.getOtp().isBlank()) {
                throw new OtpCodeIsNotSent("otp code is not sent");
            }
            TwoFactorContext twoFactorContext = context.get();
            OtpVerifyResponse otpVerifyResponse = verifyOtp(twoFactorContext, loginRequest.getOtp());
            if (otpVerifyResponse.success()) {
                UserPrincipal principal = (UserPrincipal) customUserDetailsService.loadUserByUsername(
                        user.getNationalCode()
                );

                String jwt = tokenProvider.generateToken(
                        new UsernamePasswordAuthenticationToken(
                                principal,
                                null,
                                principal.getAuthorities()
                        )
                );
            } else {
                return new LoginResponse()
                        .setLoginStatus("failed")
                        .setRemainingAttempts(String.valueOf(otpVerifyResponse.remainingAttempts()))
                        .setRemainingAttempts(String.valueOf(otpVerifyResponse.remainingAttempts()));
            }
        }

        UserPrincipal principal = (UserPrincipal) customUserDetailsService.loadUserByUsername(
                user.getNationalCode()
        );

        String jwt = tokenProvider.generateToken(
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        principal.getAuthorities()
                )
        );

        return new LoginResponse()
                .setLoginStatus("success")
                .setNationalCode(user.getNationalCode())
                .setMobileNumber(user.getPhoneNumber());
    }

//    public ResponseEntity<JwtAuthenticationResponse> verifyLoginOtp(OtpVerificationRequest otpRequest, String authToken) {
//    }

    public ResponseEntity<ApiResponse> registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByNationalCode(registerRequest.getNationalCode()) || userRepository.existsByPhoneNumber(registerRequest.getPhoneNumber())) {
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
        User user = userRepository.findByNationalCode(forgotPasswordRequest.getUsername())
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
                user.getNationalCode()
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
        User user = new User();

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
