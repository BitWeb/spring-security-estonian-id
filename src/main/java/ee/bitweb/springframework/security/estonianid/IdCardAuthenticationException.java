package ee.bitweb.springframework.security.estonianid;

import ee.bitweb.springframework.security.estonianid.authentication.IdCardAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

/**
 * Created by taavisikk on 5/10/16.
 */
public class IdCardAuthenticationException extends AuthenticationException {

    private final IdCardAuthenticationToken token;

    public IdCardAuthenticationException(String msg, IdCardAuthenticationToken token, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public IdCardAuthenticationException(String msg, IdCardAuthenticationToken token) {
        this(msg, token, null);
    }

    public IdCardAuthenticationToken getToken() {
        return token;
    }
}
