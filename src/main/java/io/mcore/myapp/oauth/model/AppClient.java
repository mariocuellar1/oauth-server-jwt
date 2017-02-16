package io.mcore.myapp.oauth.model;

import java.util.Arrays;
import java.util.Collection;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document(collection = "app_clients")
public class AppClient {

    @Id
    @Field("client_id")
    public String clientId;

    @Field("client_secret")
    public String clientSecret;
    
    @Field("scopes")
    public String scopes;
    
    @Field("grant_types")
    public String grantTypes;
    
    public Collection<String> getScopes() {
    	if (scopes != null) {
    		return Arrays.asList(scopes.split(","));
    	}
    	return null;
    }
    
    public Collection<String> getGrantTypes() {
    	if (grantTypes != null) {
    		return Arrays.asList(grantTypes.split(","));
    	}
    	return null;
    }
    
}
