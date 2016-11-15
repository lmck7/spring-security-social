package lmck.spring.security.social;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class OAuth1AuthenticationToken extends AbstractSocialAuthenticationToken<OAuth1Token> {

	private static final long serialVersionUID = -8454762081737782978L;

	public OAuth1AuthenticationToken(OAuth1Token authToken, String provider) {
		super(authToken, provider);
	}

	public OAuth1AuthenticationToken(UserDetails userDetails, OAuth1Token authToken, String provider,
			Collection<? extends GrantedAuthority> authorities) {
		super(userDetails, authToken, provider, authorities);
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof OAuth1AuthenticationToken)) {
			return false;
		}
		return super.equals(obj);
	}
	
}
