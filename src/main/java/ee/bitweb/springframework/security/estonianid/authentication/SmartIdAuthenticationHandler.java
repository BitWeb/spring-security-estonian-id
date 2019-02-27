package ee.bitweb.springframework.security.estonianid.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.bitweb.springframework.security.estonianid.SmartIdAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by taavisikk on 2/26/19.
 */
public class SmartIdAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException e) throws IOException, ServletException {

        if (e.getCause() instanceof UsernameNotFoundException) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            respond(response, SmartIdAuthenticationSession.AuthenticationStatus.USER_NOT_FOUND.name(),
                    SmartIdAuthenticationSession.AuthenticationStatus.USER_NOT_FOUND, null);
        } else {
            SmartIdAuthenticationException sIdEx = (SmartIdAuthenticationException) e;
            SmartIdAuthenticationToken token = sIdEx.getToken();
            SmartIdAuthenticationSession authSession = token.getAuthSession();

            respond(response, authSession.getErrorCode(), authSession.getStatus(), authSession.getVerificationCode());
        }
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        SmartIdAuthenticationToken token = (SmartIdAuthenticationToken) authentication;
        SmartIdAuthenticationSession authSession = token.getAuthSession();

        respond(response, authSession.getErrorCode(), authSession.getStatus(), authSession.getVerificationCode());
    }

    private void respond(HttpServletResponse response, String errorCode,
                         SmartIdAuthenticationSession.AuthenticationStatus status, String verificationCode)
            throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> content = new HashMap<String, Object>();
        content.put("errorCode", errorCode);
        content.put("status", status);
        content.put("verificationCode", verificationCode);

        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), content);
    }
}
