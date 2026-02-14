package com.blog.utils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.blog.service.CustomUserDetailsService;

import java.io.IOException;
import java.util.Collection;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	private final JwtUtil jwtUtil;
	private final CustomUserDetailsService customUserDetailsService;

	public JwtRequestFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService) {
		this.jwtUtil = jwtUtil;
		this.customUserDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		final String authorizationHeader = request.getHeader("Authorization");

		if (authorizationHeader != null) {
			/*
			 * Validates whether authorizationHeader contain bearer token or not.
			 * */
			String email = null;
			String jwt = null;

			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				//any JWT token follows Bearer Authentication.
				/*
				 * This is a JWT standard format
				 * Spring Security expects tokens in this form
				 * */
				jwt = authorizationHeader.substring(7);
				/* 
				 * In Authorization header,token will be stored in this format.
				 * Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyQGdtYWlsLmNvbSJ9.XYZ
				 * Bearer is type of token.
				 * After Bearer, the actual JWT token is there.
				 * If not removed, 
				 * - Signature validation fails
				 * - Token parsing fails
				 * - end up with MalformedJwtException
				*/
				email = jwtUtil.extractSubject(jwt);
				
				/*
				 * Authorization Header
        					|
        					v
				  "Bearer eyJhbGciOi..."
        					|
        					v
					 Remove "Bearer "
        					|
        					v
				JWT Parser (expects raw token to extract subject) 
				 * 
				 * */
				
			}

			if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				//Check if email exists & user is not already authenticated
				/*
				 * if email != null,
					already extracted email from JWT token
					Means: Token is valid
				 * getAuthentication()==null,
				   Spring Security hasn’t authenticated this request yet	
				 * */
				
				UserDetails userDetails = null;

				userDetails = customUserDetailsService.loadUserByUsername(email);
				/*
				 * Returns UserDetails object containing:
					- username (email)
					- password (ignored here)
					- roles / authorities
					- other fields of user.
				 * 
				 * */
				Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities() != null
						? userDetails.getAuthorities()
						: null;
				//Returns roles(authorities) will be returned from userDetails and stored inside authorities
				
				var authToken = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
						userDetails, null, authorities);
				/*
				 * manually creating an Authentication object
				 * Spring Security, consider this user as authenticated
				 * */
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				/*
				 * Adds:-
				   - IP address
				   - Session ID
				 * Mostly used for logging & auditing.
				 * */
				SecurityContextHolder.getContext().setAuthentication(authToken);
				/*
				 * Stores authenticated user in SecurityContext
				 * Security comes to know about the info on the userDetails coz stored in SecurityContextHolder
				 * */
			}
		}
		chain.doFilter(request, response);
		/*
		 * Checks for any other filter(as we don't have any other 
  					|
  					v
			DispatcherServlet
  					|
  					v
				Controller
		 * 
		 * */
	}
}
