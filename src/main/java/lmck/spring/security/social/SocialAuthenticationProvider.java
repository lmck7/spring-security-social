package lmck.spring.security.social;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionFactory;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UserProfile;
import org.springframework.social.connect.support.OAuth2ConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;

public class SocialAuthenticationProvider implements AuthenticationProvider {

	private final ConnectionFactoryLocator connectionFactoryLocator;
	private final DynamicUserDetailsService dynamicUserDetailsService;
	private DynamicUserDetailsChecker socialUserDetailsChecker =  (dynamicUserDetails, provider) -> {
		new AccountStatusUserDetailsChecker().check(dynamicUserDetails);
		if (!StringUtils.equals(provider, dynamicUserDetails.getAuthenticator())) {
			throw new BadCredentialsException("Mismatched authentication provider");
		}
	};
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public SocialAuthenticationProvider(ConnectionFactoryLocator connectionFactoryLocator,
			DynamicUserDetailsService dynamicUserDetailsService) {
		super();
		this.connectionFactoryLocator = connectionFactoryLocator;
		this.dynamicUserDetailsService = dynamicUserDetailsService;
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) {
		SocialAuthenticationToken authRequest = (SocialAuthenticationToken) authentication;
       	ConnectionFactory<?> connFactory = connectionFactoryLocator.getConnectionFactory(authRequest.getProvider());
    	if (connFactory instanceof OAuth2ConnectionFactory) {
    		OAuth2ConnectionFactory<?> oauth2ConnFactory = (OAuth2ConnectionFactory<?>) connFactory;
    		AccessGrant accessGrant = new AccessGrant(authRequest.getCredentials().toString());
    		Connection<?> conn = oauth2ConnFactory.createConnection(accessGrant);
    		UserProfile userProfile = conn.fetchUserProfile();
    		String email = userProfile.getEmail();
    		DynamicUserDetails userDetails = getUserDetails(email);
    		if (userDetails == null) {
    			throw new BadCredentialsException("Bad credentials");
    		}
    		socialUserDetailsChecker.check(userDetails, authRequest.getProvider());
    		return new SocialAuthenticationToken(userDetails, authRequest.getCredentials().toString(), 
    			authRequest.getProvider(), userDetails.getAuthorities());
    	} else {
    		throw new BadCredentialsException("Invalid authentication provider");
    	}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return SocialAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	public void setSocialUserDetailsChecker(DynamicUserDetailsChecker socialUserDetailsChecker) {
		this.socialUserDetailsChecker = socialUserDetailsChecker;
	}

	private DynamicUserDetails getUserDetails(String email) {
		try {
			return dynamicUserDetailsService.loadUserByUsername(email);
		} catch (UsernameNotFoundException e) {
			logger.warn(String.format("Failed to find user %s", email), e);
			throw new BadCredentialsException("Bad credentials");
		}
	}

}
