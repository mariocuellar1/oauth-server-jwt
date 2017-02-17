package io.mcore.myapp.oauth;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import io.mcore.myapp.oauth.model.AppClient;
import io.mcore.myapp.oauth.model.AppUser;
import io.mcore.myapp.oauth.repository.AppClientsRepository;
import io.mcore.myapp.oauth.repository.AppUsersRepository;

@SpringBootApplication
public class AuthserverApplication extends WebMvcConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

	@Configuration
	protected static class UserDetailsSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		AppUserDetailsService userDetailsService;

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
		}

		@Bean
		public PasswordEncoder passwordEncoder() {
			PasswordEncoder encoder = new BCryptPasswordEncoder();
			return encoder;
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private AppClientsUserDetailsService appClientsUserDetailsService;

		@Autowired
		AppUserDetailsService userDetailsService;

		@Bean
		public JwtAccessTokenConverter jwtAccessTokenConverter() {
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), "myapp01".toCharArray())
					.getKeyPair("myapp");
			converter.setKeyPair(keyPair);
			return converter;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.withClientDetails(appClientsUserDetailsService);
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager).userDetailsService(userDetailsService)
					.accessTokenConverter(jwtAccessTokenConverter());
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()")
					.passwordEncoder(new BCryptPasswordEncoder());
		}

	}

	@Service
	protected static class AppClientsUserDetailsService implements ClientDetailsService {

		@Autowired
		AppClientsRepository appClientsRepository;

		@Override
		public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
			AppClient client = appClientsRepository.findByClientId(clientId);
			BaseClientDetails clientDetails = new BaseClientDetails();
			clientDetails.setClientId(client.clientId);
			clientDetails.setClientSecret(client.clientSecret);
			clientDetails.setScope(client.getScopes());
			clientDetails.setAuthorizedGrantTypes(client.getGrantTypes());
			return clientDetails;
		}

	}

	@Service
	public class AppUserDetailsService implements UserDetailsService {

		@Autowired
		private AppUsersRepository userRepository;

		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			AppUser user = userRepository.findByUserName(username);
			if (user == null) {
				throw new UsernameNotFoundException(username);
			} else {
				UserDetails details = new org.springframework.security.core.userdetails.User(user.userName,
						user.password, true, true, true, true, user.getRoles());
				return details;
			}
		}
	}

}
