package ee.bitweb.springframework.security.estonianid.filter;

import ee.bitweb.springframework.security.estonianid.authentication.IdCardAuthenticationHandler;
import ee.bitweb.springframework.security.estonianid.authentication.IdCardAuthenticationToken;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.GenericFilterBean;
import sun.security.provider.X509Factory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by taavisikk on 5/10/16.
 */
public class IdCardAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    private String filterProcessesUrl = "/j_spring_eid_security_check";
    private AuthenticationManager authenticationManager;
    private ApplicationEventPublisher applicationEventPublisher;
    private AuthenticationSuccessHandler authenticationSuccessHandler = new IdCardAuthenticationHandler();
    private AuthenticationFailureHandler authenticationFailureHandler = new IdCardAuthenticationHandler();

    private boolean getClientCertFromHeader = true;
    private String clientCertHeaderName = "X-Client-Certificate";

    @Override
    public void afterPropertiesSet() throws ServletException {
        super.afterPropertiesSet();
        Assert.notNull(authenticationManager, "authenticationManager must be specified");
        Assert.notNull(applicationEventPublisher, "applicationEventPublisher must be specified");
    }
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!request.getRequestURI().contains(filterProcessesUrl)) {
            chain.doFilter(request, response);
            return;
        }

        logger.debug("Request requires IdCard authentication");

        Authentication token;

        try {
            token = attemptAuthentication(request);
            if (ObjectUtils.isEmpty(token)) {
                return;
            }

            successfulAuthentication(request, response, token);
        } catch (AuthenticationException e) {
            unsuccessfulAuthentication(request, response, e);
        }
    }

    Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
        logger.debug("Attempting IdCard authentication");

        X509Certificate certificate = obtainCert(request);
        return authenticationManager.authenticate(new IdCardAuthenticationToken(certificate));
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                          Authentication authentication) throws IOException, ServletException {
        logger.debug("Successfully authenticated with IdCard authentication: " + authentication);

        // When a populated Authentication object is placed in the SecurityContextHolder,
        // the user is authenticated.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        applicationEventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authentication, getClass()));

        authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException e) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        logger.debug("IdCard authentication failed: {}", e);
        authenticationFailureHandler.onAuthenticationFailure(request, response, e);
    }

    private X509Certificate obtainCert(HttpServletRequest request) {
        if(getClientCertFromHeader) {
            X509Certificate cert = null;
            String certStr = request.getHeader(clientCertHeaderName);

            if (!ObjectUtils.isEmpty(certStr)) {
                byte[] certArr = DatatypeConverter
                        .parseBase64Binary(certStr.replaceAll(X509Factory.BEGIN_CERT, "")
                        .replaceAll(X509Factory.END_CERT, ""));
                try {
                    cert = (X509Certificate) CertificateFactory
                            .getInstance("X.509")
                            .generateCertificate(new ByteArrayInputStream(certArr));
                } catch (CertificateException e) {
                    logger.error(e);
                    return null;
                }

            } else {
                logger.debug("No client certificate");
            }

            return cert;
        } else {
            X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

            if (certs != null && certs.length > 0) {
                return certs[0];
            } else {
                logger.debug("No client certificate");
                return null;
            }
        }
    }

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public ApplicationEventPublisher getApplicationEventPublisher() {
        return applicationEventPublisher;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    public AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
        return authenticationSuccessHandler;
    }

    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    public AuthenticationFailureHandler getAuthenticationFailureHandler() {
        return authenticationFailureHandler;
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public boolean isGetClientCertFromHeader() {
        return getClientCertFromHeader;
    }

    public void setGetClientCertFromHeader(boolean getClientCertFromHeader) {
        this.getClientCertFromHeader = getClientCertFromHeader;
    }

    public String getClientCertHeaderName() {
        return clientCertHeaderName;
    }

    public void setClientCertHeaderName(String clientCertHeaderName) {
        this.clientCertHeaderName = clientCertHeaderName;
    }
}
