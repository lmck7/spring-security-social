package lmck.spring.security.social;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class SocialAuthenticationFilter extends OncePerRequestFilter {

	private AuthenticationManager authenticationManager;
	private final String authorizationHeaderName;
	private final String providerHeaderName;
	private final String authorizationMethodPrefix;

	private Logger log = LoggerFactory.getLogger(getClass());
	
	public SocialAuthenticationFilter(AuthenticationManager authenticationManager,
			String authorizationHeaderName, String providerHeaderName,
			String authorizationMethodPrefix) {
		super();
		this.authenticationManager = authenticationManager;
		this.authorizationHeaderName = authorizationHeaderName;
		this.providerHeaderName = providerHeaderName;
		this.authorizationMethodPrefix = authorizationMethodPrefix;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {

		String header = request.getHeader(authorizationHeaderName);
		String provider = request.getHeader(providerHeaderName);

		if (header == null || !header.startsWith(authorizationMethodPrefix) || StringUtils.isBlank(provider)) {
			chain.doFilter(request, response);
			return;
		}
		
		String authenticationToken = StringUtils.substringAfter(header, authorizationMethodPrefix);

		try {
			log.debug(
				String.format("Social authentication authorization header found with token %s", 
					authenticationToken));
					
			if (authenticationIsRequired(authenticationToken)) {
				SocialAuthenticationToken authRequest = 
						new SocialAuthenticationToken(authenticationToken, provider);
				Authentication authResult = this.authenticationManager.authenticate(authRequest);
				log.debug("Authentication success: " + authResult);
				SecurityContextHolder.getContext().setAuthentication(authResult);
			}

		}
		catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();
			log.debug("Authentication request for failed: " + failed);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			return;
		}

		chain.doFilter(request, response);
	}

	private boolean authenticationIsRequired(String authenticationToken) {
		Authentication existingAuth = SecurityContextHolder.getContext()
				.getAuthentication();
		if (existingAuth == null || !existingAuth.isAuthenticated()) {
			return true;
		}
		if (existingAuth instanceof SocialAuthenticationToken
				&& !existingAuth.getCredentials().equals(authenticationToken)) {
			return true;
		}
		if (existingAuth instanceof AnonymousAuthenticationToken) {
			return true;
		}
		return false;
	}
	
}
