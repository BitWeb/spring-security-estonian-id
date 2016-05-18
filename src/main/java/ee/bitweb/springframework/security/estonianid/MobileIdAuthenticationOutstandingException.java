package ee.bitweb.springframework.security.estonianid;

import ee.bitweb.springframework.security.estonianid.authentication.MobileIdAuthenticationToken;

/**
 * Created by taavisikk on 5/10/16.
 */
public class MobileIdAuthenticationOutstandingException extends MobileIdAuthenticationException {

    public MobileIdAuthenticationOutstandingException(String msg, MobileIdAuthenticationToken token, Throwable t) {
        super(msg, token, t);
    }

    public MobileIdAuthenticationOutstandingException(String msg, MobileIdAuthenticationToken token) {
        super(msg, token);
    }
}
