package com.demo.spring_jwt.user;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User implements UserDetails {
	
	@Id
	@GeneratedValue
	private Integer id;
	
	private String firstname;
	
	private String lastname;
	
	private String email;
	
	private String password;
	
	@Enumerated(EnumType.STRING)
	private Role role;

	// Returns a collection of authorities (roles) that the user has.
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority(role.name()));
	}

	// Returns the username of the user. In this case, it's the user's email.
	@Override
	public String getUsername() {
		return email;
	}

	// Checks if the user's account has not expired. You return 'true' to indicate the account never expires.
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// Checks if the user's account is not locked. You return 'true' to indicate the account is never locked.
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// Checks if the user's credentials (password) are not expired. You return 'true' to indicate credentials never expire.
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// Checks if the user is enabled. You return 'true' to indicate the user is always enabled.
	@Override
	public boolean isEnabled() {
		return true;
	}

	// Returns the user's password.
	@Override
	public String getPassword() {
		return password;
	}
}