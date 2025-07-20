package com.mobilefund.config;

import com.mobilefund.Exception.CustomAuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class TwoFactorAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public TwoFactorAuthenticationProvider(UserDetailsService userDetailsService,
                                           PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        try {
            UserDetails user = userDetailsService.loadUserByUsername(username);

            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new BadCredentialsException("Invalid password");
            }

            return new UsernamePasswordAuthenticationToken(
                    user,
                    null,
                    user.getAuthorities()
            );

        } catch (UsernameNotFoundException ex) {
            try {
                throw new CustomAuthenticationException("User not found");
            } catch (CustomAuthenticationException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}