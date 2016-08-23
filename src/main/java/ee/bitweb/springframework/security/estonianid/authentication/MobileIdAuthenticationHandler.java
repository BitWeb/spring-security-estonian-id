package ee.bitweb.springframework.security.estonianid.authentication;

import ee.bitweb.springframework.security.estonianid.MobileIdAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by taavisikk on 5/10/16.
 */
public class MobileIdAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException e) throws IOException, ServletException {

        if (e.getCause() instanceof UsernameNotFoundException) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            respond(response, HttpServletResponse.SC_UNAUTHORIZED, "USER_NOT_FOUND", null);
        } else {
            MobileIdAuthenticationException mIdEx = (MobileIdAuthenticationException) e;
            MobileIdAuthenticationToken token = mIdEx.getToken();
            MobileIdAuthenticationSession authSession = token.getAuthSession();

            respond(response, authSession.getErrorCode(), authSession.getStatus(), authSession.getChallengeId());
        }
    }

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        MobileIdAuthenticationToken token = (MobileIdAuthenticationToken) authentication;
        MobileIdAuthenticationSession authSession = token.getAuthSession();

        respond(response, authSession.getErrorCode(), authSession.getStatus(), authSession.getChallengeId());
    }

    private void respond(HttpServletResponse response, Integer errorCode, String status, String challengeId)
            throws IOException {

        String content = String.format("{\"errorCode\": %s, \"status\": \"%s\", \"challengeId\": \"%s\"}",
                errorCode, status, challengeId);

        response.setContentType("application/json");
        response.getWriter().write(content);
    }
}
