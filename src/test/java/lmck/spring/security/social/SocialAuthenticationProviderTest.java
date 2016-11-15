package lmck.spring.security.social;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UserProfile;
import org.springframework.social.connect.support.OAuth2ConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.web.client.HttpClientErrorException;

@RunWith(MockitoJUnitRunner.class)
public class SocialAuthenticationProviderTest {

	@InjectMocks
	private SocialAuthenticationProvider socialAuthenticationProvider;
	
	@Mock
	private ConnectionFactoryLocator connectionFactoryLocator;
	@Mock
	private DynamicUserDetailsService dynamicUserDetailsService;
	@Mock @SuppressWarnings("rawtypes")
	private OAuth2ConnectionFactory connectionFactory;
	@Mock @SuppressWarnings("rawtypes")
	private Connection connection;

	private OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken("token1", "google");				
	private DynamicUserDetails userDetails = new DefaultDynamicUserDetails("james.woolimooloo@gmail.com", "", true, "google", 
			Arrays.asList(new SimpleGrantedAuthority("role1")), Arrays.asList(new SimpleGrantedAuthority("role2")));

	
	@Before @SuppressWarnings("unchecked")
	public void before() {
		when(connectionFactoryLocator.getConnectionFactory("google")).thenReturn(connectionFactory);
		when(connectionFactory.createConnection(any(AccessGrant.class))).thenReturn(connection);
		UserProfile userProfile = new UserProfile("1234", "james woolimooloo", "james", "woolimooloo", "james.woolimooloo@gmail.com", "1234423");
		when(connection.fetchUserProfile()).thenReturn(userProfile);
	}
	
	@Test 
	public void authenticate_validAuthRequest_shouldReturnSocialAuthenticationToken() {
		// given
		when(dynamicUserDetailsService.loadUserByUsername("james.woolimooloo@gmail.com")).thenReturn(userDetails);
		
		// when
		Authentication auth = socialAuthenticationProvider.authenticate(authRequest);
		
		//
		assertTrue(auth instanceof OAuth2AuthenticationToken);
		OAuth2AuthenticationToken resultSocialAuthToken = (OAuth2AuthenticationToken) auth;
		assertEquals(userDetails, resultSocialAuthToken.getPrincipal());
		assertEquals("token1", resultSocialAuthToken.getCredentials());
		assertEquals(Arrays.asList(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2")), 
			resultSocialAuthToken.getAuthorities());
	}

	@Test(expected=BadCredentialsException.class)
	public void authenticate_noUserDetails_shouldThrowBadCredentialsException() {
		// given
		when(dynamicUserDetailsService.loadUserByUsername("james.woolimooloo@gmail.com")).thenReturn(null);
		
		// when
		socialAuthenticationProvider.authenticate(authRequest);
	}

	@Test(expected=BadCredentialsException.class)
	public void authenticate_usernameNotFoundException_shouldThrowBadCredentialsException() {
		// given
		when(dynamicUserDetailsService.loadUserByUsername("james.woolimooloo@gmail.com")).thenThrow(new UsernameNotFoundException("not found"));
		
		// when
		socialAuthenticationProvider.authenticate(authRequest);
	}

	@Test(expected=BadCredentialsException.class)
	public void authenticate_connectionToProviderFailed_shouldThrowBadCredentialsException() {
		// given
		when(connectionFactory.createConnection(any(AccessGrant.class))).thenThrow(HttpClientErrorException.class);
		
		// when
		socialAuthenticationProvider.authenticate(authRequest);
	}

	@Test(expected=BadCredentialsException.class)
	public void authenticate_unknownProvider_shouldThrowBadCredentialsException() {
		// given
		when(connectionFactoryLocator.getConnectionFactory("google")).thenThrow(IllegalArgumentException.class);
		
		// when
		socialAuthenticationProvider.authenticate(authRequest);
	}

	@Test(expected=BadCredentialsException.class)
	public void authenticate_unexpectedException_shouldThrowBadCredentialsException() {
		// given
		when(connectionFactory.createConnection(any(AccessGrant.class))).thenThrow(Exception.class);
		
		// when
		socialAuthenticationProvider.authenticate(authRequest);
	}	
}
