package ee.bitweb.springframework.security.estonianid.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ObjectUtils;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by taavisikk on 5/9/16.
 */
public class EstonianIdUserDetails implements UserDetails {

    private Object id = null;
    private final String idCode;
    private final String givenName;
    private final String surname;
    private final String screenName;
    private final Set<GrantedAuthority> authorities;

    public EstonianIdUserDetails(String idCode, String givenName, String surname, String screenName,
                                 Collection<GrantedAuthority> authorities) {
        this(idCode, givenName, surname, screenName, authorities, null);
    }

    public EstonianIdUserDetails(String idCode, String givenName, String surname, String screenName,
                                 Collection<GrantedAuthority> authorities, Object id) {
        if (ObjectUtils.isEmpty(idCode)) {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }
        if (authorities == null) {
            throw new RuntimeException("Cannot pass a null GrantedAuthority collection");
        }
        for (GrantedAuthority authority : authorities) {
            if (authority == null) {
                throw new RuntimeException("GrantedAuthority list cannot contain any null elements");
            }
        }
        this.idCode = idCode;
        this.givenName = givenName;
        this.surname = surname;
        this.screenName = screenName;
        this.authorities = new HashSet<GrantedAuthority>(authorities);
        this.id = id;
    }

    public Object getId() {
        return id;
    }

    public Set<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public String getIdCode() {
        return idCode;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getSurname() {
        return surname;
    }

    public String getScreenName() {
        return screenName;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(super.toString());
        stringBuilder.append(": ");

        if (this.authorities != null) {
            stringBuilder.append("Granted authorities: ");

            GrantedAuthority[] grantedAuthorities = {};
            this.authorities.toArray(grantedAuthorities);

            for (int i = 0; i < grantedAuthorities.length; i++) {
                if (i > 0) {
                    stringBuilder.append(",");
                }
                stringBuilder.append(grantedAuthorities[i].getAuthority());
            }
        } else {
            stringBuilder.append("Not granted any authorities");
        }
        stringBuilder.append("; IdCode: ");
        stringBuilder.append(idCode);
        stringBuilder.append("; Givenname: ");
        stringBuilder.append(givenName);
        stringBuilder.append("; Surname: ");
        stringBuilder.append(surname);

        return stringBuilder.toString();
    }

    public String getPassword() {
        throw new NotImplementedException();
    }

    public String getUsername() {
        return idCode;
    }

    public boolean isAccountNonExpired() {
        throw new NotImplementedException();
    }

    public boolean isAccountNonLocked() {
        throw new NotImplementedException();
    }

    public boolean isCredentialsNonExpired() {
        throw new NotImplementedException();
    }

    public boolean isEnabled() {
        throw new NotImplementedException();
    }

}
