package ee.bitweb.springframework.security.estonianid;

import ee.bitweb.springframework.security.estonianid.authentication.SmartIdAuthenticationToken;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationPendingException extends SmartIdAuthenticationException {

    public SmartIdAuthenticationPendingException(String msg, SmartIdAuthenticationToken token, Throwable t) {
        super(msg, token, t);
    }

    public SmartIdAuthenticationPendingException(String msg, SmartIdAuthenticationToken token) {
        super(msg, token);
    }
}
