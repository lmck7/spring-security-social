package lmck.spring.security.social;

import org.springframework.security.core.userdetails.UserDetails;

public interface DynamicUserDetails extends UserDetails {
	String getAuthenticator();
}
