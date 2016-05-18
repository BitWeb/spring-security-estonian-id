package ee.bitweb.springframework.security.estonianid;

import ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

/**
 * Created by taavisikk on 5/10/16.
 */
public class MobileIdAuthenticationException extends AuthenticationException {

    private final MobileIdAuthenticationToken token;

    public MobileIdAuthenticationException(String msg, MobileIdAuthenticationToken token, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public MobileIdAuthenticationException(String msg, MobileIdAuthenticationToken token) {
        this(msg, token, null);
    }

    public MobileIdAuthenticationToken getToken() {
        return token;
    }
}
