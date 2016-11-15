package lmck.spring.security.social;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.social.oauth1.OAuthToken;

public class OAuth1Token extends OAuthToken {
	
	private static final long serialVersionUID = -6509857412447981142L;

	public OAuth1Token(String token, String secret) {
		super(token, secret);
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17, 37).
				append(getValue()).
				append(getSecret()).
			    toHashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) { 
			return false; 
		}
		if (obj == this) { 
			return true; 
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		OAuth1Token rhs = (OAuth1Token) obj;
		return new EqualsBuilder()
			.appendSuper(super.equals(obj))
		    .append(getValue(), rhs.getValue())
		    .append(getSecret(), rhs.getSecret())
		    .isEquals();
	}

}
