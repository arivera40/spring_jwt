package com.demo.spring_jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
	
	private final JwtAuthenticationFilter jwtAuthFilter;
	
	private final AuthenticationProvider authenticationProvider;
	
	// At the application startup Spring Security will try to look for a bean
	// of type SecurityFilterChain. This bean is responsible for configuring
	// all the HTTP security of our application.
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.csrf()	// Cross-Site Request Forgery. It is a security feature aimed at preventing unauthorized actions on behalf of an authenticated user
			.disable()	// Disable CSRF as the application is stateless and each request is expected to have JWT token. CSRF typically relies on tokens stored in session or cookies.
			.authorizeHttpRequests()
			.requestMatchers("/api/v1/auth/**")	// Need to authorize http requests in order to whitelist certain urls i.e. when logging in or registering, a token is not required
			.permitAll()	// Permit all the requests above
			.anyRequest()	// All other requests
			.authenticated()	// Should be authenticated.
			.and()
			.sessionManagement()	// Configure session management: we want all requests to be authenticated, in which case, we do not want to store the authentication state/session state so.. session should be stateless
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)	// Making it stateless means each request should be authenticated
			.and()
			.authenticationProvider(authenticationProvider)
			.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);	// We want to add the filter we created before to intercept the http request
			
		
		return http.build();
	}
}
