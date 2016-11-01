package lmck.spring.security.social;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

public class DefaultDynamicUserDetails implements DynamicUserDetails {

	private static final long serialVersionUID = 7759891064832291014L;
	private String username;
	private String authenticator;
	private String password;
	private boolean enabled;
	private List<GrantedAuthority> authorities;
	private List<GrantedAuthority> groupAuthorities;
	
	public DefaultDynamicUserDetails(String username, String password, 
			boolean enabled, String authenticator,
			List<GrantedAuthority> authorities,
			List<GrantedAuthority> groupAuthorities) {
		super();
		this.username = username;
		this.authenticator = authenticator;
		this.password = password;
		this.enabled = enabled;
		this.authorities = authorities;
		this.groupAuthorities = groupAuthorities;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> allAuthorities = new ArrayList<>(authorities);
		allAuthorities.addAll(groupAuthorities);
		return allAuthorities;
	}

	@Override
	public String getAuthenticator() {
		return authenticator;
	}
	
	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

}
