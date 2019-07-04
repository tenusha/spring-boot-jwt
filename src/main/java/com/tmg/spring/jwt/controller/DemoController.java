package com.tmg.spring.jwt.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.tmg.spring.jwt.model.User;
import com.tmg.spring.jwt.repository.UserRepository;
import com.tmg.spring.jwt.security.JwtTokenProvider;

@RestController
public class DemoController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@PostMapping("/users/signin")
	public Object login(@RequestBody final Optional<User> user) {

		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(user.get().getUsername(), user.get().getPassword()));
		return jwtTokenProvider.createToken(user.get().getUsername(),
				userRepository.findByUsername(user.get().getUsername()).getRoles());
	}

	@PostMapping("/users/signup")
	public String register(@RequestBody User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		userRepository.save(user);
		return jwtTokenProvider.createToken(user.getUsername(), user.getRoles());
	}

	@GetMapping("/api/protected")
	public String protectedData() {
		return "Protected Data";
	}
	
	@GetMapping("/api/admin/protected")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public String protectedAdminData() {
		return "Protected Admin Data";
	}
	
	@GetMapping("/api/user/protected")
	@PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
	public String protectedUserData() {
		return "Protected User Data";
	}
}
