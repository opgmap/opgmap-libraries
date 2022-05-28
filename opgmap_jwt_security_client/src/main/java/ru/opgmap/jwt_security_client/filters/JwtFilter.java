package ru.opgmap.jwt_security_client.filters;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.opgmap.jwt_security_client.authentication.JwtAuthentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    public static final String AUTH_JWT = "JWT-X-TOKEN";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader(AUTH_JWT);

        if (token != null) {
            JwtAuthentication jwtAuthentication = new JwtAuthentication(token.split(" ")[1]);
            SecurityContextHolder.getContext().setAuthentication(jwtAuthentication);
        } else {
            SecurityContextHolder.getContext().setAuthentication(null);
        }
        filterChain.doFilter(request, response);
    }

}
