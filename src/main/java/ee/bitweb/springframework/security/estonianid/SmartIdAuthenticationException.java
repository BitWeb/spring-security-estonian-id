package ee.bitweb.springframework.security.estonianid;

import ee.bitweb.springframework.security.estonianid.authentication.SmartIdAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationException extends AuthenticationException {

    private SmartIdAuthenticationToken token;

    public SmartIdAuthenticationException(String msg, SmartIdAuthenticationToken token, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public SmartIdAuthenticationException(String msg, SmartIdAuthenticationToken token) {
        this(msg, token, null);
    }

    public SmartIdAuthenticationToken getToken() {
        return token;
    }
}
