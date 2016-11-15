package lmck.spring.security.social;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class SocialSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private String authorizationHeaderName = "Authorization";
	private String authorizationMethodPrefix = "Bearer ";
	private String oauth1TokenHeaderName = "oauth_token";
	private String oauth1TokenSecretHeaderName = "oauth_token_secret";
	private String providerHeaderName = "Provider";
	
	protected SocialSecurityConfigurer() {}

	public static SocialSecurityConfigurer create() {
		return new SocialSecurityConfigurer();
	}
	
	public SocialSecurityConfigurer providerHeaderName(String providerHeaderName) {
		this.providerHeaderName = providerHeaderName;
		return this;
	}
		
	@Override
	public void configure(HttpSecurity http) throws Exception {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		OAuth2AuthenticationFilter oauth2AuthenticationFilter = 
				new OAuth2AuthenticationFilter(authenticationManager, authorizationHeaderName, 
						providerHeaderName, authorizationMethodPrefix);
		oauth2AuthenticationFilter = postProcess(oauth2AuthenticationFilter);
		OAuth1AuthenticationFilter oauth1AuthenticationFilter =
				new OAuth1AuthenticationFilter(authenticationManager, oauth1TokenHeaderName, 
						oauth1TokenSecretHeaderName, providerHeaderName);
		http.addFilterAfter(oauth2AuthenticationFilter, BasicAuthenticationFilter.class);
		http.addFilterAfter(oauth1AuthenticationFilter, BasicAuthenticationFilter.class);
	}
	
}
