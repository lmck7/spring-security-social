package lmck.spring.security.social;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class SocialSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private String authorizationHeaderName = "Authorization";
	private String providerHeaderName = "Provider";
	private String authorizationMethodPrefix = "Bearer ";
	
	protected SocialSecurityConfigurer() {}

	public static SocialSecurityConfigurer begin() {
		return new SocialSecurityConfigurer();
	}
	
	public SocialSecurityConfigurer authorizationHeaderName(String authorizationHeaderName) {
		this.authorizationHeaderName = authorizationHeaderName; 
		return this;
	}
	
	public SocialSecurityConfigurer providerHeaderName(String providerHeaderName) {
		this.providerHeaderName = providerHeaderName;
		return this;
	}
	
	public SocialSecurityConfigurer authorizationMethodPrefix(String authorizationMethodPrefix) {
		this.authorizationMethodPrefix = authorizationMethodPrefix;
		return this;
	}
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		SocialAuthenticationFilter socialAuthenticationFilter = 
				new SocialAuthenticationFilter(authenticationManager, authorizationHeaderName, 
						providerHeaderName, authorizationMethodPrefix);
		socialAuthenticationFilter = postProcess(socialAuthenticationFilter);
		http.addFilterAfter(socialAuthenticationFilter, BasicAuthenticationFilter.class);
	}
	
}
