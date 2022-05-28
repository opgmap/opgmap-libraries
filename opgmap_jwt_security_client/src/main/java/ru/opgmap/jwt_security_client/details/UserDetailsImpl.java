package ru.opgmap.jwt_security_client.details;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class UserDetailsImpl implements UserDetails {

    private UUID id;
    private String token;

    private List<String> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public String getPassword() {
        return token;
    }

    @Override
    public String getUsername() {
        return String.valueOf(id);
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
        return true;
    }

    public String getToken() {
        return token;
    }

}
