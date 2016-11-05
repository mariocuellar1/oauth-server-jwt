package io.mcore.ride.sharing.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import io.mcore.ride.sharing.oauth.model.AppClient;

public interface AppClientsRepository extends MongoRepository<AppClient, String> {
	public AppClient findByClientId(String clientId);
}
