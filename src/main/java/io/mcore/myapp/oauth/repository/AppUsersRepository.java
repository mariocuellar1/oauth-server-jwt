package io.mcore.myapp.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import io.mcore.myapp.oauth.model.AppUser;

public interface AppUsersRepository extends MongoRepository<AppUser, String> {
	public AppUser findByUserName(String userName);
}
