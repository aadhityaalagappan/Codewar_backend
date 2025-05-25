package com.codewar.code.config;

import com.codewar.code.filter.JwtFilter;
import com.codewar.code.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Autowired
    private UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
        http.csrf().disable().authorizeHttpRequests(auth ->
                auth.requestMatchers("/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated());
        /*If the request contains a valid JWT, the user is authenticated early in the filter chain.

        If invalid/missing, it falls through and will eventually be rejected (unless it's a permitted endpoint like /auth/**).*/
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * This method creates an AuthenticationManager bean — a core component that handles user authentication (i.e., username/password checking).
     *
     * What It Does:
     * http.getSharedObject(AuthenticationManagerBuilder.class): retrieves the builder to configure how Spring should authenticate.
     *
     * .userDetailsService(...): tells Spring Security to use your custom method for loading user details (see method #2).
     *
     * .passwordEncoder(...): defines how passwords should be encoded — here, using BCrypt.
     *
     * .build(): builds the final AuthenticationManager object.
     *
     *  Why You Need It:
     * Spring Security will use this AuthenticationManager to:
     *
     * Check credentials during login
     *
     * Verify password (by comparing raw input with encoded password from DB)
     *
     *
     * **/

    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService()).passwordEncoder(new BCryptPasswordEncoder())
                .and().build();
    }
    /*
    This defines a custom UserDetailsService — a function Spring calls to load user details from your database during authentication.
    */

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .map(user -> new org.springframework.security.core.userdetails.User(
                        user.getEmail(), user.getPassword(), List.of(new SimpleGrantedAuthority(user.getRole()))
                )).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }


}
