package io.mcore.ride.sharing.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import io.mcore.ride.sharing.oauth.model.AppUser;

public interface AppUsersRepository extends MongoRepository<AppUser, String> {
	public AppUser findByUserName(String userName);
}
