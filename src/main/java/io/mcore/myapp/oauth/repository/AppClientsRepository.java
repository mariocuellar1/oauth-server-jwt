package io.mcore.myapp.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import io.mcore.myapp.oauth.model.AppClient;

public interface AppClientsRepository extends MongoRepository<AppClient, String> {
	public AppClient findByClientId(String clientId);
}
