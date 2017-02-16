package io.mcore.myapp.oauth.model;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Document(collection = "app_users")
public class AppUser {

    @Id
    @Field("user_name")
    public String userName;

    @Field("password")
    public String password;
    
    @Field("roles")
    public String roles;
    
    public Collection<GrantedAuthority> getRoles() {
    	Collection<GrantedAuthority> result = new ArrayList<>();
    	if (roles != null) {
    		String[] _roles = roles.split(",");
    		for (String role : _roles) {
				result.add(new SimpleGrantedAuthority(role));
			}
    	}
    	if (result.size() == 0) {
    		result.add(new SimpleGrantedAuthority("USER"));
    	}
    	return result;
    }
    
}
