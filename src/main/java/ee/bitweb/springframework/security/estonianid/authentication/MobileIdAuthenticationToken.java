package ee.bitweb.springframework.security.estonianid.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

/**
 * Created by taavisikk on 5/10/16.
 */
public class MobileIdAuthenticationToken extends EstonianIdAuthenticationToken {

    private String userPhoneNo;
    private String userLanguageCode;
    private MobileIdAuthenticationSession authSession;

    public MobileIdAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String userPhoneNo,
                                       String userLanguageCode, MobileIdAuthenticationSession authSession) {
        super(authorities);
        this.userPhoneNo = userPhoneNo;
        this.userLanguageCode = userLanguageCode;
        this.authSession = authSession;
    }

    public MobileIdAuthenticationToken(String userPhoneNo, String userLanguageCode) {
        this(AuthorityUtils.NO_AUTHORITIES, userPhoneNo, userLanguageCode, null);
    }

    public MobileIdAuthenticationToken(String userPhoneNo) {
        this(userPhoneNo, "EST");
    }

    public String getUserPhoneNo() {
        return userPhoneNo;
    }

    public void setUserPhoneNo(String userPhoneNo) {
        this.userPhoneNo = userPhoneNo;
    }

    public String getUserLanguageCode() {
        return userLanguageCode;
    }

    public void setUserLanguageCode(String userLanguageCode) {
        this.userLanguageCode = userLanguageCode;
    }

    public MobileIdAuthenticationSession getAuthSession() {
        return authSession;
    }

    public void setAuthSession(MobileIdAuthenticationSession authSession) {
        this.authSession = authSession;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(super.toString());
        stringBuilder.append("; UserPhoneNo: ");
        stringBuilder.append(userPhoneNo);
        stringBuilder.append("; UserLanguageCode: ");
        stringBuilder.append(userLanguageCode);

        return stringBuilder.toString();
    }
}
