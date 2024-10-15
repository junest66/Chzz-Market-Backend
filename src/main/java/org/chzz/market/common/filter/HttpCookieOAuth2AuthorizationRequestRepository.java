package org.chzz.market.common.filter;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import org.chzz.market.common.util.CookieUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;

@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements OAuth2AuthorizedClientRepository {
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    private static final int cookieExpireSeconds = 180;

    @Override
    public OAuth2AuthorizedClient loadAuthorizedClient(String clientRegistrationId,
                                                       Authentication principal,
                                                       HttpServletRequest request) {
        return Optional.ofNullable(CookieUtil.getCookieByName(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME))
                .map(cookie -> CookieUtil.deserialize(cookie, OAuth2AuthorizedClient.class))
                .orElse(null);
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
                                     HttpServletRequest request, HttpServletResponse response) {
        if (authorizedClient == null) {
            removeAuthorizedClient(authorizedClient.getClientRegistration().getRegistrationId(), principal, request,
                    response);
            return;
        }

        CookieUtil.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                CookieUtil.serialize(authorizedClient), cookieExpireSeconds);
        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            CookieUtil.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
                                       HttpServletRequest request, HttpServletResponse response) {
        removeAuthorizationRequestCookies(response);
    }

    public void removeAuthorizationRequestCookies(HttpServletResponse response) {
        CookieUtil.expireCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtil.expireCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME);
    }
}
