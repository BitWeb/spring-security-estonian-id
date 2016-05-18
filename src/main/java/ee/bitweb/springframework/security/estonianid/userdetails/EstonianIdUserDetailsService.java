package ee.bitweb.springframework.security.estonianid.userdetails;

import ee.bitweb.springframework.security.estonianid.authentication.EstonianIdAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;

/**
 * Created by taavisikk on 5/12/16.
 */
public interface EstonianIdUserDetailsService extends AuthenticationUserDetailsService<EstonianIdAuthenticationToken> {

    ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails saveUserDetails(EstonianIdAuthenticationToken token);

    ee.bitweb.springframework.security.estonianid.userdetails.EstonianIdUserDetails updateUserDetails(EstonianIdUserDetails userDetails, EstonianIdAuthenticationToken token);
}
