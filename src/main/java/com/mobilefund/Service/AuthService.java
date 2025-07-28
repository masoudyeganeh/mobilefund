package com.mobilefund.Service;

import com.mobilefund.Dto.*;
import com.mobilefund.Exception.*;
import com.mobilefund.Model.*;
import com.mobilefund.Redis.Config.Repository.RedisAuthRepository;
import com.mobilefund.Redis.Config.Repository.TwoFactorRepository;
import com.mobilefund.Repository.OtpCacheRepository;
import com.mobilefund.Repository.RoleRepository;
import com.mobilefund.Repository.UserRepository;
import com.mobilefund.Responses.ApiResponse;
import com.mobilefund.Responses.LoginResponse;
import com.mobilefund.config.CustomUserDetailsService;
import com.mobilefund.config.JwtTokenProvider;
import com.mobilefund.config.OtpContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
    private final CustomUserDetailsService customUserDetailsService;
    private final TwoFactorRepository twoFactorRepository;
    private final RedisAuthRepository redisAuthRepository;

    @Value("${sms.validity.seconds}")
    private int otpValiditySeconds;

    @Value("${sms.max.attempts}")
    private int maxAttempts;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    @Value("${sms.max.OtpRequests}")
    private int maxOtpRequests;

    @Value("${sms.rateLimit.Window.Minutes}")
    private int rateLimitWindowMinutes;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, CustomUserDetailsService customUserDetailsService, TwoFactorRepository twoFactorRepository, JwtTokenProvider tokenProvider, SmsService smsService, ExternalValidationService validationService, OtpCacheRepository otpCacheRepository, RedisAuthRepository redisAuthRepository) {
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
        this.redisAuthRepository = redisAuthRepository;
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

    public LoginResponse authenticateUser(LoginRequest loginRequest) {

        User user = findUserByUsername(loginRequest.getUsername());

        if (!user.isTwoFactorAuth()) {
            return handleSFAuthentication(user, loginRequest);
        } else {
            return handle2FAuthentication(user, loginRequest);
        }
    }


    private LoginResponse handleSFAuthentication(User user, LoginRequest loginRequest) {
        validatePassword(user, loginRequest.getPassword());

        UserPrincipal principal = loadPrincipal(user);
        String jwt = generateAndStoreJwt(user, principal);

        return buildSuccessResponse(user, jwt);
    }

    private LoginResponse handle2FAuthentication(User user, LoginRequest loginRequest) {
        Optional<OtpContext> contextOpt = redisAuthRepository.getOtpContext("login", user.getPhoneNumber());

        if (contextOpt.isEmpty()) {
            if (!redisAuthRepository.incrementOtpRequestCount(user.getPhoneNumber(), maxOtpRequests, rateLimitWindowMinutes)) {
                throw new OtpCodeIsNotSent("Too many OTP requests. Please wait.");
            }
            return sendOtp(user);
        }

        OtpContext context = contextOpt.get();

        long secondsElapsed = Duration.between(contextOpt.get().getIssuedAt(), LocalDateTime.now()).getSeconds();
        long secondsRemaining = otpValiditySeconds - secondsElapsed;

        if (secondsRemaining <= 0) {
            throw new BadCredentialsException("Otp is expired");
        }

        if (context.getAttempts() <= 0) {
            redisAuthRepository.deleteOtpContext("login", user.getPhoneNumber());
            throw new BadCredentialsException("Maximum OTP attempts exceeded.");
        }

        if (!context.getOtp().equals(loginRequest.getOtp())) {
            context.setAttempts(context.getAttempts() - 1);
            redisAuthRepository.saveOtpContext("login", user.getPhoneNumber(), context, otpValiditySeconds);
            return new LoginResponse()
                    .setLoginStatus(LoginStatus.OTP_INVALID)
                    .setRemainingTime(String.valueOf(secondsRemaining))
                    .setRemainingAttempts(String.valueOf(context.getAttempts()));
        }

        // Valid OTP
        redisAuthRepository.deleteOtpContext("login", user.getPhoneNumber());
        validatePassword(user, loginRequest.getPassword());

        UserPrincipal principal = loadPrincipal(user);
        String jwt = generateAndStoreJwt(user, principal);

        return buildSuccessResponse(user, jwt);
    }

    private void validatePassword(User user, String rawPassword) {
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    private UserPrincipal loadPrincipal(User user) {
        return (UserPrincipal) customUserDetailsService.loadUserByUsername(user.getNationalCode());
    }

    private String generateAndStoreJwt(User user, UserPrincipal principal) {
        String jwt = tokenProvider.generateToken(
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        principal.getAuthorities()
                )
        );
        redisAuthRepository.saveJwtToken(user.getNationalCode(), jwt, jwtExpirationInMs);
        return jwt;
    }

    private LoginResponse buildSuccessResponse(User user, String jwt) {
        return new LoginResponse()
                .setLoginStatus(LoginStatus.SUCCESS)
                .setNationalCode(user.getNationalCode())
                .setMobileNumber(user.getPhoneNumber())
                .setJwt(jwt);
    }

    private LoginResponse sendOtp(User user) {
        String otp = generateOtp();

        OtpContext context = new OtpContext()
                .setOtp(otp)
                .setAttempts(maxAttempts)
                .setIssuedAt(LocalDateTime.now());

        redisAuthRepository.saveOtpContext("login", user.getPhoneNumber(), context, otpValiditySeconds);
        smsService.sendSms(user.getPhoneNumber(), otp);

        return new LoginResponse()
                .setLoginStatus(LoginStatus.OTP_REQUIRED)
                .setRemainingTime(String.valueOf(otpValiditySeconds))
                .setRemainingAttempts(String.valueOf(maxAttempts));
    }

    public LoginResponse registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByNationalCode(registerRequest.getNationalCode())) {
            throw new OtpCodeIsNotSent("national code is already exists");
        }

        if (userRepository.existsByPhoneNumber(registerRequest.getPhoneNumber())) {
            throw new OtpCodeIsNotSent("phone number is already exists");
        }

        // Check shahkar service
        boolean isValid = true;

        if (!isValid) {
            throw new OtpCodeIsNotSent("phone number doesn't belong to nationalCode");
        }

        // Generate OTP
        User user = User.builder()
                .nationalCode(registerRequest.getNationalCode())
                .phoneNumber(registerRequest.getPhoneNumber())
                .build();

        return sendOtp(user);
    }

//    public ResponseEntity<?> verifyRegistrationOtp(OtpVerificationRequest otpRequest) {
//        Optional<OtpCache> otpCache = otpCacheRepository.findByPhoneNumber(otpRequest.getPhoneNumber());
//
//        if (otpCache.isEmpty() || !otpCache.get().getOperationType().equals("REGISTER")) {
//            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP request"));
//        }
//
//        if (LocalDateTime.now().isAfter(otpCache.get().getExpiryTime())) {
//            return ResponseEntity.badRequest().body(new ApiResponse(false, "OTP expired"));
//        }
//
//        if (!otpCache.get().getOtp().equals(otpRequest.getOtp())) {
//            return ResponseEntity.badRequest().body(new ApiResponse(false, "Invalid OTP"));
//        }
//
//        RegisterRequest registerRequest = new RegisterRequest();
//        registerRequest.setNationalCode(otpCache.get().getNationalCode());
//        registerRequest.setUsername(otpCache.get().getUsername());
//        registerRequest.setPassword(otpCache.get().getTempData()); // This is already encoded
//        registerRequest.setPhoneNumber(otpRequest.getPhoneNumber());
//
//        // Create user
//        User user = new User(
//                registerRequest.getNationalCode(),
//                registerRequest.getPassword(), // Already encoded password
//                registerRequest.getPhoneNumber()
//        );
//
//        Set<Role> roles = new HashSet<>();
//        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                .orElseThrow();
//        roles.add(userRole);
//
//        user.setRoles(roles);
//        userRepository.save(user);
//
//        // Clean up OTP cache
//        otpCacheRepository.delete(otpCache.get());
//
//        return ResponseEntity.ok(new ApiResponse(true, "User registered successfully!"));
//    }

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
