package com.example.books.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@Component
public class BooksWsAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {
    private static final Logger LOGGER = LoggerFactory.getLogger(BooksWsAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        response.addHeader("WWW-Authenticate", "Basic realm=" + getRealmName());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        final Map<String, Object> body = new HashMap<>();
        body.put("Status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("Error", "Unauthorized");
        body.put("Timestamp", now.format(formatter));
        body.put("Message", authException.getMessage());
        body.put("Path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
        LOGGER.error("Unauthorized error: {}", authException.getMessage() + " on" + " " + now.format(formatter));
    }

    @Override
    public void afterPropertiesSet() {
        setRealmName("basicRealm");
        super.afterPropertiesSet();
    }
}
