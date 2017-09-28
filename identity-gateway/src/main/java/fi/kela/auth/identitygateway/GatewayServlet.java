package fi.kela.auth.identitygateway;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

public class GatewayServlet extends GenericServlet {
	private static final long serialVersionUID = 1L;
	// TODO: These are static for now. Should be specified using parameters 
	private static final String GATEWAY_PROVIDER = "http://localhost:8080";
	private static final String PROXY_TARGET = "http://localhost:19082";
	private static final String COOKIE_PATH = "/";
	private static final String CALLBACK_SERVICE_CONTEXT = "/auth-cb";
	private static final String LOGOUT_SERVICE_CONTEXT = "/logout";
	private static final String ERROR_CONTEXT = "/error";
	private static final String AUTH_SERVICE_CONTEXT = "/auth";
	private static final String ERROR_REDIRECT_TARGET = "http://error";
	private static final String LOGOUT_REDIRECT_TARGET = "http://logout";
	private static final String AUTH_TOKEN_COOKIE = "K_JWT";
	private static final String STATE_COOKIE = "S_AUTH";
	private static final Logger logger = Logger.getLogger(GatewayServlet.class);
	private OpenIDClient openIDClient;

	public GatewayServlet() {
		openIDClient = new OpenIDClient();
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
		} else if (!isAuthenticationTokenSet(req) && !isAllowAnonymous(req)) {
			redirectToAuthentication(req, res);
		} else {
			proxy(req, res);
		}
	}

	private String getCallbackURI() {
		return GATEWAY_PROVIDER + CALLBACK_SERVICE_CONTEXT;
	}

	private boolean isAuthenticationCallback(HttpServletRequest req) {
		return CALLBACK_SERVICE_CONTEXT.equals(req.getServletPath());
	}

	private void authenticate(HttpServletRequest req, HttpServletResponse res) throws IOException {
		String stateId = req.getParameter("state");
		String state = getCookie(req, STATE_COOKIE);
		// TODO: Verify state
		
		String code = req.getParameter("code");
		String token = openIDClient.getToken(code, getCallbackURI());

		// TODO: Fetch destination from state
		String origin = state;
		logger.info("User authenticated, redirecting to origin " + origin);
		res.addCookie(createAuthCookie(token, -1));
		res.sendRedirect(origin);
	}

	private void logout(HttpServletRequest req, HttpServletResponse res) throws IOException {
		logger.info("Logging out");
		res.addCookie(createAuthCookie(null, 0));
		res.sendRedirect(LOGOUT_REDIRECT_TARGET);
	}
	
	private Cookie createAuthCookie(String content, int maxAge) {
		Cookie cookie = new Cookie(AUTH_TOKEN_COOKIE, content);
		cookie.setPath(COOKIE_PATH);
		cookie.setMaxAge(maxAge);
		return cookie;
	}
	

	private boolean isError(HttpServletRequest req) {
		return ERROR_CONTEXT.equals(req.getServletPath());
	}

	private boolean isLogout(HttpServletRequest req) {
		return LOGOUT_SERVICE_CONTEXT.equals(req.getServletPath());
	}

	private boolean isAllowAnonymous(HttpServletRequest req) {
		return AUTH_SERVICE_CONTEXT.equals(req.getServletPath());
	}

	private void redirectToError(HttpServletRequest req, HttpServletResponse res) throws IOException {
		logger.info("Redirecting to error page");
		res.sendRedirect(ERROR_REDIRECT_TARGET);
	}

	private void redirectToAuthentication(HttpServletRequest req, HttpServletResponse res) throws IOException {
		logger.info("Redirecting to authentication service");
		String stateId = generateStateID();
		res.addCookie(createStateCookie(req, stateId));
		res.sendRedirect(openIDClient.getLoginProviderURL(stateId, getCallbackURI()));
	}
	
	private String generateStateID() {
		return UUID.randomUUID().toString().replace("-", "");
	}
	
	private Cookie createStateCookie(HttpServletRequest req, String state) {
		String origin = req.getServletPath();
		Cookie cookie = new Cookie(STATE_COOKIE, origin);
		cookie.setPath(COOKIE_PATH);
		cookie.setMaxAge(15 * 60);
		return cookie;
	}
	
	private boolean containsCookie(HttpServletRequest req, String name) {
		Cookie []cookies = req.getCookies();
		if (cookies == null) {
			return false;
		}
		return Arrays.asList(cookies).stream().filter(c -> name.equals(c.getName())).findFirst().isPresent();
	}
	
	private String getCookie(HttpServletRequest req, String name) {
		return Arrays.asList(req.getCookies()).stream().filter(c -> name.equals(c.getName())).findFirst().get().getValue();
	}

	private boolean isAuthenticationTokenSet(HttpServletRequest req) {
		return containsCookie(req, AUTH_TOKEN_COOKIE);
	}
	
	private String getAuthenticationToken(HttpServletRequest req) {
		return getCookie(req, AUTH_TOKEN_COOKIE);
	}

	private void proxy(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		String target = getProxyTarget(req);
		logger.info("Proxying request to " + target);
		HttpURLConnection connection = (HttpURLConnection) new URL(target).openConnection();
		proxyRequest(req, connection);
		proxyResponse(res, connection);
	}

	private String getProxyTarget(HttpServletRequest req) {
		StringBuilder target = new StringBuilder(PROXY_TARGET);
		target.append(req.getServletPath());
		String queryString = req.getQueryString();
		if (queryString != null) {
			target.append('?').append(queryString);
		}
		return target.toString();
	}

	private void proxyRequest(HttpServletRequest req, HttpURLConnection connection)
			throws ProtocolException, IOException {
		connection.setRequestMethod(req.getMethod());
		connection.setDoInput(true);
		Collections.list(req.getHeaderNames())
				.forEach(name -> connection.setRequestProperty(name, req.getHeader(name)));
		String token = getAuthenticationToken(req);
		connection.setRequestProperty("Authorization", "Bearer " + token);

		if (Arrays.asList("POST", "PUT").contains(req.getMethod().toUpperCase())) {
			connection.setDoOutput(true);
			try (InputStream is = req.getInputStream(); OutputStream os = connection.getOutputStream()) {
				proxy(is, os);
			}
		}
	}

	private void proxyResponse(HttpServletResponse res, HttpURLConnection connection) throws IOException {
		int rc = connection.getResponseCode();

		res.setContentType(connection.getContentType());
		res.setStatus(rc);
		connection.getHeaderFields().entrySet().stream().filter(e -> e.getKey() != null)
				.forEach(e -> res.setHeader(e.getKey(), e.getValue().get(0)));
		
		int contentLength = connection.getContentLength();
		if (contentLength > 0) {
			res.setContentLength(contentLength);
		}
		if (rc >= 200 && rc < 400) {
			proxyContent(res, connection);
		} else {
			proxyErrorContent(res, connection);
		}
	}

	private void proxyContent(HttpServletResponse res, HttpURLConnection connection) throws IOException {
		try (InputStream is = connection.getInputStream(); OutputStream os = res.getOutputStream()) {
			proxy(is, os);
		}
	}

	private void proxyErrorContent(HttpServletResponse res, HttpURLConnection connection) throws IOException {
		try (InputStream is = connection.getErrorStream(); OutputStream os = res.getOutputStream()) {
			proxy(is, os);
		}
	}

	private void proxy(InputStream is, OutputStream os) throws IOException {
		byte[] buf = new byte[8196];
		int cnt;
		while ((cnt = is.read(buf)) > 0) {
			os.write(buf, 0, cnt);
		}
		os.flush();
	}
}
