package com.mobilefund.config;

import com.mobilefund.Model.UserPrincipal;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final SecretKey jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    public JwtTokenProvider(SecretKey jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public Authentication getAuthentication(String jwtToken) {
        String username = getUsername(jwtToken); // extract username from token

        // You can optionally load user details from DB here if needed
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    public String getUsername(String token) {
        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String generateToken(UsernamePasswordAuthenticationToken authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .claim("username", userPrincipal.getUsername())
                .claim("roles", userPrincipal.getAuthorities())
                .compact();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            logger.warn("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.warn("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.warn("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.warn("JWT claims string is empty.");
        }
        return false;
    }
}
