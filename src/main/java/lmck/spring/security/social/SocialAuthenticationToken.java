package lmck.spring.security.social;

import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class SocialAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 8511889617632566051L;
	private UserDetails userDetails;
	private String authenticationToken;
	private String provider;
	
	public SocialAuthenticationToken(String authenticationToken, String provider) {
		super(null);
		this.authenticationToken = authenticationToken;
		this.provider = provider;
		setAuthenticated(false);
	}
	
	public SocialAuthenticationToken(UserDetails userDetails, 
			String authenticationToken, String provider,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.userDetails = userDetails;
		this.authenticationToken = authenticationToken;
		this.provider = provider;
		setAuthenticated(true);
	}
	
	@Override
	public Object getCredentials() {
		return authenticationToken;
	}

	@Override
	public Object getPrincipal() {
		return userDetails;
	}

	public String getProvider() {
		return provider;
	}

	@Override
	public int hashCode() {
		int hashCode = super.hashCode();
		if (this.getProvider() != null) {
			hashCode ^= this.getProvider().hashCode();
		}
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof SocialAuthenticationToken)) {
			return false;
		}
		SocialAuthenticationToken test = (SocialAuthenticationToken) obj;
		if (!StringUtils.equals(provider, test.provider)) {
			return false;
		}
		return super.equals(obj);
	}
	
}
