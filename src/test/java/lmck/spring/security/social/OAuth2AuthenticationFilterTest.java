package lmck.spring.security.social;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;

@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthenticationFilterTest {

	@Mock
	private AuthenticationManager authenticationManager;

	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;
	@Mock
	private FilterChain chain;
	
	private String authorizationHeaderName = "Authorization";
	private String authorizationMethodPrefix = "Bearer ";
	private String providerHeaderName = "Provider";
	
	@Before
	public void before() {
		SecurityContextHolder.clearContext();
	}
	
	@Test
	public void doFilter_validToken_shouldPopulateSecurityContextAndProceed() throws Exception {
		// given
		OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken("token1", "google");
		DefaultDynamicUserDetails userDetails = new DefaultDynamicUserDetails("user1@example.com", "", true, "google", null, null);
		OAuth2AuthenticationToken authResult = new OAuth2AuthenticationToken(userDetails, "token1", "google", null);
		when(request.getHeader(authorizationHeaderName)).thenReturn("Bearer token1");
		when(request.getHeader(providerHeaderName)).thenReturn("google");
		when(authenticationManager.authenticate(authRequest)).thenReturn(authResult);
		OAuth2AuthenticationFilter socialAuthenticationFilter = new OAuth2AuthenticationFilter(authenticationManager, 
				authorizationHeaderName, providerHeaderName, authorizationMethodPrefix);
		
		// when
		socialAuthenticationFilter.doFilter(request, response, chain);
			
		// then
		OAuth2AuthenticationToken storedAuthToken = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
		assertEquals(storedAuthToken, authResult);
		verify(chain).doFilter(request, response);
	}
	
	@Test
	public void doFilter_noAuthorizationHeader_shouldProceed() throws Exception {
		// given
		when(request.getHeader(authorizationHeaderName)).thenReturn(null);
		OAuth2AuthenticationFilter socialAuthenticationFilter = new OAuth2AuthenticationFilter(authenticationManager, 
				authorizationHeaderName, providerHeaderName, authorizationMethodPrefix);
		
		// when
		socialAuthenticationFilter.doFilter(request, response, chain);
		
		// then
		verify(chain).doFilter(request, response);
	}

	
	@Test
	public void doFilter_noProviderHeader_shouldProceed() throws Exception {
		// given
		when(request.getHeader(authorizationHeaderName)).thenReturn("Bearer token1");
		when(request.getHeader(providerHeaderName)).thenReturn(null);
		OAuth2AuthenticationFilter socialAuthenticationFilter = new OAuth2AuthenticationFilter(authenticationManager, 
				authorizationHeaderName, providerHeaderName, authorizationMethodPrefix);
		
		// when
		socialAuthenticationFilter.doFilter(request, response, chain);
		
		// then
		verify(chain).doFilter(request, response);
	}
	
	@Test
	public void doFilter_authenticationException_shouldNotProceedAndRespond401() throws Exception {
		// given
		OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken("token1", "google");
		when(request.getHeader(authorizationHeaderName)).thenReturn("Bearer token1");
		when(request.getHeader(providerHeaderName)).thenReturn("google");
		when(authenticationManager.authenticate(authRequest)).thenThrow(Exception.class);
		OAuth2AuthenticationFilter socialAuthenticationFilter = new OAuth2AuthenticationFilter(authenticationManager, 
				authorizationHeaderName, providerHeaderName, authorizationMethodPrefix);
		
		// when
		socialAuthenticationFilter.doFilter(request, response, chain);
		
		// then
		verify(response).setStatus(401);
		verify(chain, never()).doFilter(request, response);
	}
	
	@Test
	public void doFilter_nullAuthenticationResult_shouldNotProceedAndRespond401() throws Exception {
		// given
		OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken("token1", "google");
		when(request.getHeader(authorizationHeaderName)).thenReturn("Bearer token1");
		when(request.getHeader(providerHeaderName)).thenReturn("google");
		when(authenticationManager.authenticate(authRequest)).thenThrow(Exception.class);
		OAuth2AuthenticationFilter socialAuthenticationFilter = new OAuth2AuthenticationFilter(authenticationManager, 
				authorizationHeaderName, providerHeaderName, authorizationMethodPrefix);
		
		// when
		socialAuthenticationFilter.doFilter(request, response, chain);
		
		// then
		verify(response).setStatus(401);
		verify(chain, never()).doFilter(request, response);
	}
	
}
