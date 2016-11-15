package lmck.spring.security.social;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class OAuth2AuthenticationTokenTest {

	private List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("role1"));
	private List<GrantedAuthority> groupAuthorities = Arrays.asList(new SimpleGrantedAuthority("role2"));
	private DynamicUserDetails userDetails = new DefaultDynamicUserDetails("username1", "password1", 
		true, "google", 
		authorities, groupAuthorities);		
	private OAuth2AuthenticationToken socialAuthToken = new OAuth2AuthenticationToken(userDetails, "token1", 
		"google", userDetails.getAuthorities());	
	
	@Test
	public void equals_sameTypeAndData_shouldReturnTrue() {
		// given
		OAuth2AuthenticationToken socialAuthTokenCompare = 
				new OAuth2AuthenticationToken(userDetails, "token1", "google", userDetails.getAuthorities());
		
		// when 
		boolean result = socialAuthToken.equals(socialAuthTokenCompare);
		
		// then
		assertTrue(result);
	}
	
	@Test
	public void equals_differentProvider_shouldReturnFalse() {
		// given
		OAuth2AuthenticationToken socialAuthTokenCompare = 
				new OAuth2AuthenticationToken(userDetails, "token1", "facebook", userDetails.getAuthorities());
		
		// when 
		boolean result = socialAuthToken.equals(socialAuthTokenCompare);
		
		// then
		assertFalse(result);
		
	}
	
	@Test
	public void equals_differentType_shouldReturnFalse() {
		// given
		AbstractAuthenticationToken abstractAuthToken = new AbstractAuthenticationToken(userDetails.getAuthorities()) {
			private static final long serialVersionUID = 1L;
			@Override
			public Object getPrincipal() {
				return userDetails;
			}
			@Override
			public Object getCredentials() {
				return socialAuthToken.getCredentials();
			}
		};
		
		// when
		boolean result = socialAuthToken.equals(abstractAuthToken);
		
		// then
		assertFalse(result);
	}	
	
}
