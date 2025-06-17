package com.example.books.service;

import com.example.books.constants.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    /*@Value("${bookws.security.jwt.token.secret}")
    String secret;*/
    @Value("${jwtSecret}")
    private String JWT_SECRET;

    private UserDetailsServiceImpl userDetailsService;

//    private static String jwtSecret = System.getenv("jwtSecret");

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager
            , UserDetailsServiceImpl userDetailsService
    ) {
        super(authenticationManager);
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws IOException, ServletException {

        // Getting the header from the request
        String authHeader = request.getHeader("Authorization");

        // Validate the Authorization header
        if(authHeader == null || authHeader.trim().length() == 0 ||
                !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        // Auth Header is present and is in valid format
        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(authHeader);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String authHeader) {

        if (authHeader != null) {
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(SecurityConstants.JWT_SECRET))
                    .build()
                    .verify(authHeader.replace("Bearer ", ""));

            if(decodedJWT != null) {
                String userNameFromJwt = decodedJWT.getSubject();

                if (userNameFromJwt != null) {
                    List<String> roles = decodedJWT.getClaim("roles").asList(String.class);

                    Set<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toSet());
                    // UserDetails userDetails = userDetailsService.loadUserByUsername(userNameFromJwt);
                    return new UsernamePasswordAuthenticationToken(userNameFromJwt, null,
                          authorities);
                }
            }
        }

        return null;
    }


}
