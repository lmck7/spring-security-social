package lmck.spring.security.social;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class DefaultDynamicUserDetailsTest {

	@Test
	public void getAuthorties_nonEmptyAuthoritiesandGroupAuthorities_shouldReturnAllOfBoth() {
		// given 
		List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("role1"), 
				new SimpleGrantedAuthority("role2"));
		List<GrantedAuthority> groupAuthorities = Arrays.asList(new SimpleGrantedAuthority("role3"), 
				new SimpleGrantedAuthority("role4"));
		DefaultDynamicUserDetails userDetails = 
				new DefaultDynamicUserDetails("user1", "password1", 
					true, "google", 
					authorities, groupAuthorities);
		
		// when 
		Collection<? extends GrantedAuthority> allUserAuthorities = userDetails.getAuthorities();
		
		// then
		assertEquals(4, allUserAuthorities.size());
		GrantedAuthority[] allUserAuthoritiesArr = new GrantedAuthority[allUserAuthorities.size()];  
		allUserAuthorities.toArray(allUserAuthoritiesArr);
		assertEquals(new SimpleGrantedAuthority("role1"), allUserAuthoritiesArr[0]);
		assertEquals(new SimpleGrantedAuthority("role2"), allUserAuthoritiesArr[1]);
		assertEquals(new SimpleGrantedAuthority("role3"), allUserAuthoritiesArr[2]);
		assertEquals(new SimpleGrantedAuthority("role4"), allUserAuthoritiesArr[3]);
	}

	
}
