package lmck.spring.security.social;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

public class DefaultDynamicUserDetails implements DynamicUserDetails {

	private static final long serialVersionUID = 7759891064832291014L;
	private String username;
	private String authenticator;
	private String password;
	private boolean enabled;
	private boolean nonExpired;
	private boolean nonLocked;
	private boolean credentialsNonExpired;
	private Collection<GrantedAuthority> authorities;
	private Collection<GrantedAuthority> groupAuthorities;
	
	public DefaultDynamicUserDetails(String username, String password, 
			boolean enabled, String authenticator,
			Collection<GrantedAuthority> authorities,
			Collection<GrantedAuthority> groupAuthorities) {
		this(username, password, enabled, authenticator, true, true, true, authorities, groupAuthorities);
	}

	public DefaultDynamicUserDetails(String username, String password, boolean enabled, 
			String authenticator, boolean nonExpired, boolean nonLocked, boolean credentialsNonExpired,
			Collection<GrantedAuthority> authorities, Collection<GrantedAuthority> groupAuthorities) {
		super();
		this.username = username;
		this.authenticator = authenticator;
		this.password = password;
		this.enabled = enabled;
		this.nonExpired = nonExpired;
		this.nonLocked = nonLocked;
		this.credentialsNonExpired = credentialsNonExpired;
		this.authorities = authorities != null ? authorities : new HashSet<>();
		this.groupAuthorities = groupAuthorities != null ? groupAuthorities : new HashSet<>();
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
		return nonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return nonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

}
