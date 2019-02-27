package ee.bitweb.springframework.security.estonianid.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by taavisikk on 5/11/16.
 */
public class IdCardAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException e) throws IOException, ServletException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        respond(response, IdCardAuthenticationService.ST_BAD_CERTIFICATE);
    }

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication a)
            throws IOException, ServletException {

        respond(response, IdCardAuthenticationService.ST_AUTHENTICATED);
    }

    private void respond(HttpServletResponse response, String status)
            throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> content = new HashMap<String, Object>();
        content.put("status", status);

        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), content);
    }
}
