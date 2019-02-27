package ee.bitweb.springframework.security.estonianid.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationToken extends EstonianIdAuthenticationToken {

    private SmartIdAuthenticationSession.CountryCode countryCode;

    private SmartIdAuthenticationSession authSession;

    public SmartIdAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String userIdCode,
                                      SmartIdAuthenticationSession.CountryCode countryCode,
                                      SmartIdAuthenticationSession authSession) {
        super(authorities);

        setUserIdCode(userIdCode);

        this.countryCode = countryCode;
        this.authSession = authSession;
    }

    public SmartIdAuthenticationToken(String userIdCode, SmartIdAuthenticationSession.CountryCode countryCode) {
        this(AuthorityUtils.NO_AUTHORITIES, userIdCode, countryCode, null);
    }

    public SmartIdAuthenticationToken(String userIdCode) {
        this(userIdCode, SmartIdAuthenticationSession.CountryCode.EE);
    }

    public SmartIdAuthenticationSession.CountryCode getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(SmartIdAuthenticationSession.CountryCode countryCode) {
        this.countryCode = countryCode;
    }

    public SmartIdAuthenticationSession getAuthSession() {
        return authSession;
    }

    public void setAuthSession(SmartIdAuthenticationSession authSession) {
        this.authSession = authSession;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(super.toString());
        stringBuilder.append("; CountryCode: ");
        stringBuilder.append(countryCode);

        return stringBuilder.toString();
    }
}
