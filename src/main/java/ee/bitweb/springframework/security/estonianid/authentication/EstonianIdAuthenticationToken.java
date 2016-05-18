package ee.bitweb.springframework.security.estonianid.authentication;

import ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Created by taavisikk on 5/9/16.
 */
public class EstonianIdAuthenticationToken extends AbstractAuthenticationToken {

    private String userIdCode;
    private String userGivenName;
    private String userSurname;

    private EstonianIdUserDetails principal;
    private Object credentials;

    public EstonianIdAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    public String getUserIdCode() {
        return userIdCode;
    }

    public void setUserIdCode(String userIdCode) {
        this.userIdCode = userIdCode;
    }

    public String getUserGivenName() {
        return userGivenName;
    }

    public void setUserGivenName(String userGivenName) {
        this.userGivenName = userGivenName;
    }

    public String getUserSurname() {
        return userSurname;
    }

    public void setUserSurname(String userSurname) {
        this.userSurname = userSurname;
    }

    public EstonianIdUserDetails getPrincipal() {
        return principal;
    }

    public void setPrincipal(EstonianIdUserDetails principal) {
        this.principal = principal;
    }

    public Object getCredentials() {
        return credentials;
    }

    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(super.toString());
        stringBuilder.append("; UserIdCode: ");
        stringBuilder.append(userIdCode);
        stringBuilder.append("; UserGivenname: ");
        stringBuilder.append(userGivenName);
        stringBuilder.append("; UserSurname: ");
        stringBuilder.append(userSurname);

        return stringBuilder.toString();
    }
}
