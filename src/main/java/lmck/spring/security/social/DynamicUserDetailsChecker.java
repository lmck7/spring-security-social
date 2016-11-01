package lmck.spring.security.social;

@FunctionalInterface
public interface DynamicUserDetailsChecker {
	void check(DynamicUserDetails toCheck, String provider);
}
