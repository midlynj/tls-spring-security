package com.example.books.security;

import com.example.books.service.JwtAuthorizationFilter;
import com.example.books.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private UserDetailsServiceImpl userDetailsService;
    private BooksWsAuthenticationEntryPoint authenticationEntryPoint;

    public SecurityConfig(BCryptPasswordEncoder bCryptPasswordEncoder, UserDetailsServiceImpl userDetailsService,
                          BooksWsAuthenticationEntryPoint authenticationEntryPoint) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userDetailsService = userDetailsService;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authManager) throws Exception {
        http.csrf(csrf -> csrf.disable())
                                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint))

                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry //.requestMatchers(HttpMethod.DELETE).hasRole("ADMIN")
                                .requestMatchers("/book/admin").hasAnyAuthority("ADMIN")
                                .requestMatchers("/book/1").hasAnyAuthority( "ADMIN","USER")
                                .requestMatchers("/book").permitAll()
                                .anyRequest().authenticated())
//                .and()
//                .addFilter(new JwtAuthenticationFilter(authManager))
                .addFilter(new JwtAuthorizationFilter(authentication -> authentication, userDetailsService))
//                .httpBasic(Customizer.withDefaults())

                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }




//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//    @Bean
//    protected DaoAuthenticationConfigurer<AuthenticationManagerBuilder, UserDetailsServiceImpl> configure(AuthenticationManagerBuilder auth) throws Exception {
//        return auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
//    }
}
