package com.demo.spring_jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.demo.spring_jwt.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
	
	private final UserRepository repository;
	
    @Bean
    public UserDetailsService userDetailsService() {
        // Return a UserDetailsService implementation as a lambda expression
        return username -> {
            // Try to find a user by their email (username)
            // If a user is found, it will be returned as a UserDetails object
            // If no user is found, a UsernameNotFoundException is thrown
            return repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        };
    }
    
    // Data access object responsible to fetch the user details and encode passwords.
    @Bean
    public AuthenticationProvider authenticationProvider() {
    	DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    	authProvider.setUserDetailsService(userDetailsService());	// Tell authProvider which UserDetailsService to use
    	authProvider.setPasswordEncoder(passwordEncoder());	// Tell authProvider which passwordEncoder in order to be able to decoder the password
    	return authProvider;
    	
    }

    // PasswordEncoder is an interface in Spring Security used for encoding passwords.
    // It provides a way to securely hash passwords before storing them in a database 
    // or comparing them during authentication.
    @Bean
	public PasswordEncoder passwordEncoder() {
    	return new BCryptPasswordEncoder();	// What is BCryptPasswordEncoder ?
	}
    
    // AuthenticationManager is an interface in Spring Security that defines the contract
    // for authenticating a user. It is responsible for authenticating a user based on the 
    // provided credentials (username and password). The AuthenticationManager typically 
    // delegates the actual authentication process to one or more AuthenticationProvider instances.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    	return config.getAuthenticationManager();
    }
}
