package lmck.spring.security.social;

import java.io.Serializable;
import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public abstract class AbstractSocialAuthenticationToken<T extends Serializable> extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 7396070464430273398L;
	private UserDetails userDetails;
	private T authToken;
	private String provider;
	
	public AbstractSocialAuthenticationToken(T authToken, String provider) {
		super(null);
		this.authToken = authToken;
		this.provider = provider;
		setAuthenticated(false);
	}
	
	public AbstractSocialAuthenticationToken(UserDetails userDetails, 
			T authToken, String provider,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.userDetails = userDetails;
		this.authToken = authToken;
		this.provider = provider;
		setAuthenticated(true);
	}

	@Override
	public T getCredentials() {
		return authToken;
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
		if (!(obj instanceof AbstractSocialAuthenticationToken)) {
			return false;
		}
		@SuppressWarnings("unchecked")
		AbstractSocialAuthenticationToken<T> test = (AbstractSocialAuthenticationToken<T>) obj;
		if (!StringUtils.equals(provider, test.provider)) {
			return false;
		}
		return super.equals(obj);
	}
	
}
