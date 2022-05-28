package ru.opgmap.jwt_security_client.provider;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import ru.opgmap.jwt_security_client.authentication.JwtAuthentication;
import ru.opgmap.jwt_security_client.details.UserDetailsImpl;

import java.util.Map;
import java.util.UUID;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Value("${auth.jwt.secret-key}")
    private String secretKey;

    @Value("${auth.jwt.aud}")
    private String aud;

    @Value("${auth.jwt.iss}")
    private String iss;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = authentication.getName();

        JwtAuthentication jwtAuthentication = new JwtAuthentication(token);
        try {
            DecodedJWT decodedJWT = decode(token);
            if (decodedJWT.getIssuer() != null && decodedJWT.getIssuer().equals(iss) &&
                     decodedJWT.getAudience() != null && decodedJWT.getAudience().contains(aud)) {
                Map<String, Claim> claims = decodedJWT.getClaims();

                UserDetails userDetails = UserDetailsImpl.builder()
                        .id(UUID.fromString(decodedJWT.getSubject()))
                        .authorities(claims.get("roles").asList(String.class))
                        .token(token)
                        .build();

                jwtAuthentication.setAuthenticated(true);
                jwtAuthentication.setUserDetails(userDetails);
            } else {
                throw new JWTVerificationException("iss or aud is null");
            }
        } catch (JWTVerificationException e) {
            jwtAuthentication = null;
        }
        return jwtAuthentication;
    }

    private DecodedJWT decode(String token) {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secretKey))
                .build();

        return verifier.verify(token);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }

}
