package ee.bitweb.springframework.security.estonianid.authentication;

import ee.bitweb.springframework.security.estonianid.IdCardAuthenticationException;
import ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import sun.security.x509.X500Name;

import java.io.IOException;
import java.security.Principal;

/**
 * Created by taavisikk on 5/11/16.
 */
public class IdCardAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private IdCardAuthenticationService authenticationService;
    protected UserDetailsService userDetailsService;

    private final Log logger = LogFactory.getLog(getClass());

    public void afterPropertiesSet() {
        Assert.notNull(authenticationService, "authenticationService must be specified");
        Assert.notNull(userDetailsService, "userDetailsService must be specified");
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        logger.info("Trying to authenticate ID card");

        IdCardAuthenticationToken token = (IdCardAuthenticationToken) authentication;

        if (ObjectUtils.isEmpty(token.getUserCert())) {
            throw new IdCardAuthenticationException("Bad certificate", token);
        }

        String userIdCode = authenticationService.checkCertificate(token.getUserCert());
        if (ObjectUtils.isEmpty(userIdCode)) {
            throw new IdCardAuthenticationException("Bad certificate", token);
        }

        token.setAuthenticated(true);
        token.setUserIdCode(userIdCode);

        Principal certPrincipal = token.getUserCert().getSubjectDN();
        if (certPrincipal instanceof X500Name) {
            try {
                token.setUserGivenName(((X500Name) certPrincipal).getGivenName());
                token.setUserSurname((((X500Name) certPrincipal).getSurname()));
            } catch (IOException e) {
                logger.error("Unexpected error reading name from cert: " + e);
                return authentication;
            }
        }

        EstonianIdUserDetails userDetails = retrieveUser(token);

        token = new IdCardAuthenticationToken(userDetails.getAuthorities(), token.getUserCert());
        token.setUserIdCode(String.valueOf(token.getUserCert().getSerialNumber()));
        token.setAuthenticated(true);
        token.setDetails(null);
        token.setPrincipal(userDetails);

        return token;
    }

    /**
     * Allows implementation specific ways to retrieve (or if needed, create/update) the user.
     *
     * @param token The authentication request
     * @return user information (never null, exception should be thrown)
     */
    protected EstonianIdUserDetails retrieveUser(IdCardAuthenticationToken token) throws AuthenticationException{
        try {
            return (EstonianIdUserDetails) userDetailsService.loadUserByUsername(token.getUserIdCode());
        } catch (UsernameNotFoundException e) {
            throw new IdCardAuthenticationException(e.getMessage(), token, e);
        }
    }

    public boolean supports(Class<?> authentication) {

        return IdCardAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthenticationService(IdCardAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
