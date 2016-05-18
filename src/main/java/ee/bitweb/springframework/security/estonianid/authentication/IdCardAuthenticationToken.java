package ee.bitweb.springframework.security.estonianid.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * Created by taavisikk on 5/10/16.
 */
public class IdCardAuthenticationToken extends EstonianIdAuthenticationToken {

    private X509Certificate userCert;

    public IdCardAuthenticationToken(Collection<GrantedAuthority> authorities, X509Certificate userCert) {
        super(authorities);
        this.userCert = userCert;
    }

    public IdCardAuthenticationToken(X509Certificate userCert) {
        this(AuthorityUtils.NO_AUTHORITIES, userCert);
    }

    public X509Certificate getUserCert() {
        return userCert;
    }

    public void setUserCert(X509Certificate userCert) {
        this.userCert = userCert;
    }
}
