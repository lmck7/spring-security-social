package lmck.spring.security.social;

import org.springframework.social.connect.UserProfile;

@FunctionalInterface
public interface UsernameExtractor {
	String extractUsername(UserProfile profile);
}
