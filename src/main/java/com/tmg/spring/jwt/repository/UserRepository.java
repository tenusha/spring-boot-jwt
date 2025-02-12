/**
 * 
 */
package com.tmg.spring.jwt.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.tmg.spring.jwt.model.User;

public interface UserRepository extends MongoRepository<User, String> {

	public User findByUsername(String username);
}
