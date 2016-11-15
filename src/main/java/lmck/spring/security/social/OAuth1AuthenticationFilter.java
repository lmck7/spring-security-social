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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class OAuth1AuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationManager authenticationManager;
	private final String oauthTokenHeaderName;
	private final String oauthTokenSecretHeaderName;
	private final String providerHeaderName;
	
	private final Logger log = LoggerFactory.getLogger(getClass());
	
	public OAuth1AuthenticationFilter(AuthenticationManager authenticationManager,
			String oauthTokenHeaderName, 
			String oauthTokenSecretHeaderName,
			String providerHeaderName) {
		super();
		this.authenticationManager = authenticationManager;
		this.oauthTokenHeaderName = oauthTokenHeaderName;
		this.oauthTokenSecretHeaderName = oauthTokenSecretHeaderName;
		this.providerHeaderName = providerHeaderName;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {

		String oauthTokenHeader = request.getHeader(oauthTokenHeaderName);
		String oauthSecretTokenHeader = request.getHeader(oauthTokenSecretHeaderName);
		String providerHeader = request.getHeader(providerHeaderName);

		if (StringUtils.isBlank(oauthTokenHeader) || StringUtils.isBlank(oauthSecretTokenHeader) || 
				StringUtils.isBlank(providerHeader)) {
			chain.doFilter(request, response);
			return;
		}
		
		try {
			log.debug(
				String.format("OAuth1 social authentication authorization header found with token %s", 
					oauthTokenHeader));
			
			OAuth1Token oauthToken = new OAuth1Token(oauthTokenHeader, oauthSecretTokenHeader);
			
			if (authenticationIsRequired(oauthToken)) {
				OAuth1AuthenticationToken authRequest = new OAuth1AuthenticationToken(oauthToken, providerHeader);
				Authentication authResult = this.authenticationManager.authenticate(authRequest);
				if (authResult == null) {
					throw new BadCredentialsException("Bad credentials");
				}
				log.debug("Authentication success: " + authResult);
				SecurityContextHolder.getContext().setAuthentication(authResult);
			}

		} catch (Exception failed) {
			SecurityContextHolder.clearContext();
			log.debug("Authentication request for failed: " + failed);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			return;
		}

		chain.doFilter(request, response);
	}

	private boolean authenticationIsRequired(OAuth1Token authenticationToken) {
		Authentication existingAuth = SecurityContextHolder.getContext()
				.getAuthentication();
		if (existingAuth == null || !existingAuth.isAuthenticated()) {
			return true;
		}
		if (existingAuth instanceof OAuth1AuthenticationToken 
				&& !existingAuth.getCredentials().equals(authenticationToken)) {
			return true;
		}
		if (existingAuth instanceof AnonymousAuthenticationToken) {
			return true;
		}
		return false;
	}
	
}
