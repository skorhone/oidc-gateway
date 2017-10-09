package fi.kela.auth.identitygateway;

import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import fi.kela.auth.identitygateway.oidcclient.OIDCService;
import fi.kela.auth.identitygateway.oidcclient.TokenNotFoundException;
import fi.kela.auth.identitygateway.oidcclient.TokenNotValidException;
import fi.kela.auth.identitygateway.proxy.ProxyService;
import fi.kela.auth.identitygateway.token.Token;
import fi.kela.auth.identitygateway.token.TokenService;
import fi.kela.auth.identitygateway.util.URLs;

public class GatewayServlet extends GenericServlet {
	private static final long serialVersionUID = 1L;
	private static final Logger logger = Logger.getLogger(GatewayServlet.class);
	private IGWConfiguration igwConfiguration;
	private OIDCService oidcService;
	private ProxyService proxyService;
	private TokenService tokenService;

	public GatewayServlet(IGWConfiguration igwConfiguration, OIDCService oidcService, ProxyService proxyService,
			TokenService tokenService) {
		this.igwConfiguration = igwConfiguration;
		this.oidcService = oidcService;
		this.proxyService = proxyService;
		this.tokenService = tokenService;
	}

	@Override
	public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
		service((HttpServletRequest) req, (HttpServletResponse) res);
	}

	protected void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		if (isError(req)) {
			redirectToError(req, res);
		} else if (isLogout(req)) {
			logout(req, res);
		} else if (isAuthenticationCallback(req)) {
			authenticate(req, res);
		} else {
			Token token = getAuthenticationTokenWithCookie(req);
			if (token == null && !isAllowAnonymous(req)) {
				redirectToAuthentication(req, res);
			} else {
				proxyService.proxy(req, res, token.getAccessToken());
			}
		}
	}

	public String getLocation(HttpServletRequest req) {
		if (igwConfiguration.getLocation() != null) {
			return igwConfiguration.getLocation();
		}
		return req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort();
	}

	private String getCallbackURI(HttpServletRequest req) {
		return URLs.concatURL(getLocation(req), igwConfiguration.getCallbackServiceContext());
	}

	private boolean isAuthenticationCallback(HttpServletRequest req) {
		return igwConfiguration.getCallbackServiceContext().equals(req.getServletPath());
	}

	private void authenticate(HttpServletRequest req, HttpServletResponse res) throws IOException {
		try {
			String stateId = req.getParameter("state");
			String code = req.getParameter("code");
			verifyCallbackParameters(stateId, code);

			StateCookie stateCookie = StateCookie.of(getCookie(req, igwConfiguration.getStateCookie()).getValue());
			verifyState(stateId, stateCookie);

			Token token = oidcService.getTokenWithAuthorizationCode(code, getCallbackURI(req));
			storeToken(res, token);
			res.sendRedirect(stateCookie.getOrigin());
			logger.info("User authenticated, redirecting to " + stateCookie.getOrigin());
		} catch (TokenNotValidException | TokenNotFoundException exception) {
			redirectToError(req, res);
		}
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

	private void logout(HttpServletRequest req, HttpServletResponse res) throws IOException {
		logger.info("Logging out");
		res.addCookie(createAuthCookie(null, 0));
		res.sendRedirect(igwConfiguration.getLogoutRedirectTarget());
	}

	private Cookie createAuthCookie(String content, int maxAge) {
		Cookie cookie = new Cookie(igwConfiguration.getSignOnCookie(), content);
		cookie.setPath(igwConfiguration.getCookiePath());
		cookie.setMaxAge(maxAge);
		return cookie;
	}

	private boolean isError(HttpServletRequest req) {
		return igwConfiguration.getErrorContext().equals(req.getServletPath());
	}

	private boolean isLogout(HttpServletRequest req) {
		return igwConfiguration.getLogoutServiceContext().equals(req.getServletPath());
	}

	private boolean isAllowAnonymous(HttpServletRequest req) {
		return igwConfiguration.getExcludedContexts().stream().anyMatch(c -> req.getServletPath().startsWith(c));
	}

	private void redirectToError(HttpServletRequest req, HttpServletResponse res) throws IOException {
		logger.info("Redirecting to error page");
		res.sendRedirect(igwConfiguration.getErrorRedirectTarget());
	}

	private void redirectToAuthentication(HttpServletRequest req, HttpServletResponse res) throws IOException {
		logger.info("Redirecting to authentication service");
		String stateId = generateStateID();
		res.addCookie(createStateCookie(req, stateId));
		res.sendRedirect(oidcService.getLoginProviderURL(stateId, getCallbackURI(req)));
	}

	private String generateStateID() {
		return UUID.randomUUID().toString().replace("-", "");
	}

	private Cookie createStateCookie(HttpServletRequest req, String state) {
		String origin = req.getServletPath();
		StateCookie stateCookie = new StateCookie(state, origin);
		Cookie cookie = new Cookie(igwConfiguration.getStateCookie(), stateCookie.toString());
		cookie.setVersion(1);
		cookie.setPath(igwConfiguration.getCookiePath());
		cookie.setMaxAge(igwConfiguration.getStateCookieExpire());
		cookie.setSecure(false);
		return cookie;
	}

	private Cookie getCookie(HttpServletRequest req, String name) {
		Cookie[] cookies = req.getCookies();
		if (cookies == null) {
			return null;
		}
		return Arrays.asList(cookies).stream().filter(c -> name.equals(c.getName())).findFirst().orElse(null);
	}

	private Token getAuthenticationTokenWithCookie(HttpServletRequest req) throws IOException {
		Token token = null;
		Cookie tokenCookie = getCookie(req, igwConfiguration.getSignOnCookie());
		if (tokenCookie != null) {
			String tokenId = tokenCookie.getValue();
			token = tokenService.get(tokenId);
			if (token != null && requiresRenewal(token)) {
				token = refreshAuthenticationToken(token, tokenId);
			}
		}
		return token;
	}

	private Token refreshAuthenticationToken(Token token, String tokenId) throws IOException {
		Token refreshedToken;
		try {
			refreshedToken = oidcService.getTokenWithRefreshToken(token.getRefreshToken());
			tokenService.update(tokenId, refreshedToken);
		} catch (TokenNotFoundException exception) {
			tokenService.remove(tokenId);
			refreshedToken = null;
		} catch (TokenNotValidException exception) {
			throw new IllegalStateException(exception);
		}
		return refreshedToken;
	}

	private boolean requiresRenewal(Token token) {
		long refreshAt = token.getExpiresAt() - igwConfiguration.getAccessTokenRefreshBefore();
		long now = System.currentTimeMillis();
		return now > refreshAt;
	}
}
