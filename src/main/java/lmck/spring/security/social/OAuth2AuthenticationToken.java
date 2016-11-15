package lmck.spring.security.social;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class OAuth2AuthenticationToken extends AbstractSocialAuthenticationToken<String> {

	private static final long serialVersionUID = 8511889617632566051L;
	
	public OAuth2AuthenticationToken(String accessToken, String provider) {
		super(accessToken, provider);
	}
	
	public OAuth2AuthenticationToken(UserDetails userDetails, 
			String authToken, String provider,
			Collection<? extends GrantedAuthority> authorities) {
		super(userDetails, authToken, provider, authorities);
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof OAuth2AuthenticationToken)) {
			return false;
		}
		return super.equals(obj);
	}
	
}
