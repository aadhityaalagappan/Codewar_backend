package com.codewar.code.filter;

import com.codewar.code.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {
    private JwtUtils jwtUtils;
    private UserDetailsService userDetailsService;

    public JwtFilter(JwtUtils jwtUtil) {
        this.jwtUtils = jwtUtil;
    }

    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization"); // Extract the JWT from the Authorization header

        if(authHeader!=null && authHeader.startsWith(("Bearer "))) {
            String token = authHeader.substring(7); // Extract the token from the header after Bearer
            String username = jwtUtils.extraUsername((token)); // Extract the username from the token


            if(username!=null && SecurityContextHolder.getContext().getAuthentication() == null) { // check if the user is already authenticated
                // - Check signature using secret
                // - Check expiration date
                // - Ensure the token's username matches the loaded user
               UserDetails userDetails = userDetailsService.loadUserByUsername((username));
               if(jwtUtils.validateToken(token, userDetails)) {
                   //  Create a Spring Security Authentication object
                   // - userDetails: represents the authenticated user
                   // - null: no credentials needed (we're authenticating via token)
                   // - userDetails.getAuthorities(): roles like ROLE_USER, ROLE_ADMIN
                   UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                   // Set this authentication into the Spring Security context
                   SecurityContextHolder.getContext().setAuthentication((authToken));

                }

            }

        }
        filterChain.doFilter(request, response); // Continue the filter chain
    }
}
