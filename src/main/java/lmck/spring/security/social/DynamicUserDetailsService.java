package lmck.spring.security.social;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface DynamicUserDetailsService extends UserDetailsService {
	@Override
	DynamicUserDetails loadUserByUsername(String username);
}
