package lmck.spring.security.social;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionFactory;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UserProfile;
import org.springframework.social.connect.support.OAuth1ConnectionFactory;
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
	private UsernameExtractor usernameExtractor = profile -> profile.getEmail();

	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public SocialAuthenticationProvider(ConnectionFactoryLocator connectionFactoryLocator,
			DynamicUserDetailsService dynamicUserDetailsService) {
		super();
		this.connectionFactoryLocator = connectionFactoryLocator;
		this.dynamicUserDetailsService = dynamicUserDetailsService;
	}
	
	@Override
	public Authentication authenticate(Authentication authRequest) {
		try {
			AbstractSocialAuthenticationToken<?> socialAuthRequest = (AbstractSocialAuthenticationToken<?>) authRequest;
	       	ConnectionFactory<?> connFactory = connectionFactoryLocator.getConnectionFactory(socialAuthRequest.getProvider());
	    	Connection<?> conn;
	       	if (connFactory instanceof OAuth2ConnectionFactory) {
	       		OAuth2AuthenticationToken oauth2AuthRequest = (OAuth2AuthenticationToken) authRequest;
	    		OAuth2ConnectionFactory<?> oauth2ConnFactory = (OAuth2ConnectionFactory<?>) connFactory;
	    		AccessGrant accessGrant = new AccessGrant(socialAuthRequest.getCredentials().toString());
	    		conn = oauth2ConnFactory.createConnection(accessGrant);
	    		DynamicUserDetails userDetails = getSocialUserDetails(conn, socialAuthRequest);
	    		socialUserDetailsChecker.check(userDetails, socialAuthRequest.getProvider());
	    		return new OAuth2AuthenticationToken(userDetails, 
	    			oauth2AuthRequest.getCredentials(), 
	    			oauth2AuthRequest.getProvider(), 
	    			userDetails.getAuthorities());
	    	} else if (connFactory instanceof OAuth1ConnectionFactory) {
	    		OAuth1AuthenticationToken oauth1AuthRequest = (OAuth1AuthenticationToken) authRequest;
	    		OAuth1ConnectionFactory<?> oauth1ConnFactory = (OAuth1ConnectionFactory<?>) connFactory;
	    		conn = oauth1ConnFactory.createConnection(oauth1AuthRequest.getCredentials());
	    		DynamicUserDetails userDetails = getSocialUserDetails(conn, socialAuthRequest);
	    		socialUserDetailsChecker.check(userDetails, socialAuthRequest.getProvider());
	    		return new OAuth1AuthenticationToken(userDetails, 
	    			oauth1AuthRequest.getCredentials(), 
		    		socialAuthRequest.getProvider(), 
		    		userDetails.getAuthorities());
	    	} else {
	    		throw new BadCredentialsException("Invalid authentication provider");
	    	} 
		} catch (Exception e) {
			logger.info("Invalid social authentication request received", e);
			throw new BadCredentialsException("Bad credentials");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AbstractSocialAuthenticationToken.class.isAssignableFrom(authentication);
	}
	
	public void setSocialUserDetailsChecker(DynamicUserDetailsChecker socialUserDetailsChecker) {
		this.socialUserDetailsChecker = socialUserDetailsChecker;
	}
	
	public void setUsernameExtractor(UsernameExtractor usernameExtractor) {
		this.usernameExtractor = usernameExtractor;
	}

	private DynamicUserDetails getUserDetails(String email) {
		try {
			return dynamicUserDetailsService.loadUserByUsername(email);
		} catch (UsernameNotFoundException e) {
			logger.warn(String.format("Failed to find user %s", email), e);
			throw new BadCredentialsException("Bad credentials");
		}
	}
	
	private DynamicUserDetails getSocialUserDetails(Connection<?> conn, AbstractSocialAuthenticationToken<?> socialAuthRequest) {
		UserProfile userProfile = conn.fetchUserProfile();
		String username = usernameExtractor.extractUsername(userProfile);
		DynamicUserDetails userDetails = getUserDetails(username);
		if (userDetails == null) {
			throw new BadCredentialsException("Bad credentials");
		}
		return userDetails;
	}

}
