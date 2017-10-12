package fi.kela.auth.identitygateway.auth;

import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;

import fi.kela.auth.identitygateway.IGWConfiguration;
import fi.kela.auth.identitygateway.oidcclient.OIDCService;
import fi.kela.auth.identitygateway.oidcclient.Token;
import fi.kela.auth.identitygateway.oidcclient.TokenNotFoundException;
import fi.kela.auth.identitygateway.util.Cookies;
import fi.kela.auth.identitygateway.util.ProxyContext;
import fi.kela.auth.identitygateway.util.URLs;

@Service
public class AuthService {
	private static final Logger logger = Logger.getLogger(AuthService.class);
	private IGWConfiguration igwConfiguration;
	private OIDCService oidcService;
	private TokenStorage tokenService;

	public AuthService(IGWConfiguration igwConfiguration, OIDCService oidcService, TokenStorage tokenService) {
		this.igwConfiguration = igwConfiguration;
		this.oidcService = oidcService;
		this.tokenService = tokenService;
	}

	/**
	 * Test, if request is authentication callback
	 * 
	 * @param proxyContext
	 * @return
	 */
	public boolean isAuthenticationCallback(ProxyContext proxyContext) {
		return igwConfiguration.getCallbackServiceContext().equals(proxyContext.getServletPath());
	}

	/**
	 * Redirect to authentication
	 * 
	 * @param proxyContext
	 */
	public void redirectToAuthentication(ProxyContext proxyContext) {
		logger.info("Redirecting to authentication service");
		String stateId = generateStateID();
		proxyContext.getResponse().addCookie(createStateCookie(proxyContext.getServletPath(), stateId));
		try {
			proxyContext.getResponse()
					.sendRedirect(oidcService.getLoginProviderURL(stateId, getCallbackURI(proxyContext.getRequest())));
		} catch (Exception exception) {
			logger.warn("Could not redirect user to authentication target", exception);
		}
	}

	/**
	 * Process authentication information (callback)
	 * 
	 * @param req
	 * @param res
	 * @param onComplete
	 * @param onError
	 */
	public void authenticate(ProxyContext proxyContext, Runnable onComplete, Consumer<? super AuthException> onError) {
		try {
			String stateId = proxyContext.getRequest().getParameter("state");
			String code = proxyContext.getRequest().getParameter("code");
			verifyCallbackParameters(stateId, code);

			StateCookie stateCookie = StateCookie
					.of(Cookies.getCookie(proxyContext.getRequest(), igwConfiguration.getStateCookie()).getValue());
			verifyState(stateId, stateCookie);

			Token token = oidcService.getTokenWithAuthorizationCode(code, getCallbackURI(proxyContext.getRequest()));
			storeToken(proxyContext.getResponse(), token);
			proxyContext.getResponse().sendRedirect(stateCookie.getOrigin());
			logger.info("User authenticated, redirecting to " + stateCookie.getOrigin());
			onComplete.run();
		} catch (Throwable error) {
			onError.accept(new AuthException("Could not authenticate user", error));
		}
	}

	/**
	 * Get authentication token
	 * 
	 * @param proxyContext
	 * @param onComplete
	 * @param onError
	 */
	public void retrieveAuthenticationToken(ProxyContext proxyContext, Consumer<Token> onComplete,
			Consumer<? super AuthException> onError) {
		try {
			Cookie tokenCookie = Cookies.getCookie(proxyContext.getRequest(), igwConfiguration.getSignOnCookie());
			if (tokenCookie == null) {
				onComplete.accept(null);
			} else {
				String tokenId = tokenCookie.getValue();
				Token token = tokenService.get(tokenId);
				if (token == null || !requiresRenewal(token)) {
					onComplete.accept(token);
				} else {
					refreshAuthenticationToken(token, tokenId, onComplete, onError);
				}
			}
		} catch (Throwable error) {
			onError.accept(new AuthException("Could not retrieve authentication token", error));
		}
	}

	/**
	 * Test, if request is logout
	 * 
	 * @param proxyContext
	 * @return
	 */
	public boolean isLogout(ProxyContext proxyContext) {
		return igwConfiguration.getLogoutServiceContext().equals(proxyContext.getServletPath());
	}

	/**
	 * Logout
	 * 
	 * @param proxyContext
	 * @param onComplete
	 */
	public void logout(ProxyContext proxyContext, Runnable onComplete) {
		try {
			logger.info("Logging out");
			proxyContext.getResponse().addCookie(createAuthCookie(null, 0));
			proxyContext.getResponse().sendRedirect(igwConfiguration.getLogoutRedirectTarget());
		} catch (Throwable error) {
			logger.warn("Could not redirect user to logout target", error);
		} finally {
			onComplete.run();
		}
	}

	private Cookie createAuthCookie(String content, int maxAge) {
		Cookie cookie = new Cookie(igwConfiguration.getSignOnCookie(), content);
		cookie.setPath(igwConfiguration.getCookiePath());
		cookie.setMaxAge(maxAge);
		return cookie;
	}

	private void refreshAuthenticationToken(Token token, String tokenId, Consumer<Token> onComplete,
			Consumer<? super AuthException> onError) {
		Token refreshedToken;
		try {
			try {
				refreshedToken = oidcService.getTokenWithRefreshToken(token.getRefreshToken());
				tokenService.update(tokenId, refreshedToken);
			} catch (TokenNotFoundException exception) {
				refreshedToken = null;
				tokenService.remove(tokenId);
			}
			onComplete.accept(refreshedToken);
		} catch (Throwable error) {
			onError.accept(new AuthException(error));
		}
	}

	private boolean requiresRenewal(Token token) {
		long refreshAt = token.getExpiresAt() - igwConfiguration.getAccessTokenRefreshBefore();
		long now = System.currentTimeMillis();
		return now > refreshAt;
	}

	private void storeToken(HttpServletResponse res, Token token) {
		String tokenId = tokenService.store(token);
		res.addCookie(createAuthCookie(tokenId, (int) TimeUnit.DAYS.toSeconds(365)));
	}

	private void verifyCallbackParameters(String stateId, String code) {
		if (stateId == null || stateId.isEmpty()) {
			throw new IllegalArgumentException("State parameter is required for callback");
		}
		if (code == null || code.isEmpty()) {
			throw new IllegalArgumentException("Code parameter is required for callback");
		}
	}

	private void verifyState(String stateId, StateCookie stateCookie) {
		if (!stateId.equals(stateCookie.getState())) {
			throw new IllegalArgumentException(
					"State does not match. Received: " + stateId + " Expected: " + stateCookie.getState());
		}
	}

	private String getLocation(HttpServletRequest req) {
		if (igwConfiguration.getLocation() != null) {
			return igwConfiguration.getLocation();
		}
		return req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort();
	}

	private String getCallbackURI(HttpServletRequest req) {
		return URLs.concatURL(getLocation(req), igwConfiguration.getCallbackServiceContext());
	}

	private String generateStateID() {
		return UUID.randomUUID().toString().replace("-", "");
	}

	private Cookie createStateCookie(String origin, String state) {
		StateCookie stateCookie = new StateCookie(state, origin);
		Cookie cookie = new Cookie(igwConfiguration.getStateCookie(), stateCookie.toString());
		cookie.setVersion(1);
		cookie.setPath(igwConfiguration.getCookiePath());
		cookie.setMaxAge(igwConfiguration.getStateCookieExpire());
		cookie.setSecure(false);
		return cookie;
	}
}
