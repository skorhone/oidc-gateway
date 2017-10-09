package fi.kela.auth.identitygateway.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;

import fi.kela.auth.identitygateway.IGWConfiguration;
import fi.kela.auth.identitygateway.util.ProxyContext;
import fi.kela.auth.identitygateway.util.URLs;

@Service
public class ProxyService {
	private static final Logger logger = Logger.getLogger(ProxyService.class);
	private IGWConfiguration appPropValues;

	public ProxyService(IGWConfiguration appPropValues) {
		this.appPropValues = appPropValues;
	}

	public void proxy(ProxyContext proxyContext, String authenticationToken)
			throws OpenConnectionException, ProxyRequestException, ProxyResponseException {
		String target = getProxyTarget(proxyContext);
		logger.info("Proxying request to " + target);
		HttpURLConnection connection = openConnection(target);
		proxyRequest(proxyContext.getRequest(), connection, authenticationToken);
		proxyResponse(proxyContext.getResponse(), connection);
	}

	private HttpURLConnection openConnection(String target) throws OpenConnectionException {
		try {
			return (HttpURLConnection) new URL(target).openConnection();
		} catch (Exception exception) {
			throw new OpenConnectionException(exception);
		}
	}

	private String getProxyTarget(ProxyContext proxyContext) {
		return URLs.concatURL(appPropValues.getProxyTarget(), proxyContext.getServletPath(), proxyContext.getQueryString());
	}

	private void proxyRequest(HttpServletRequest req, HttpURLConnection connection, String authenticationToken)
			throws ProxyRequestException {
		try {
			connection.setRequestMethod(req.getMethod());
			connection.setDoInput(true);
			Collections.list(req.getHeaderNames())
					.forEach(name -> connection.setRequestProperty(name, req.getHeader(name)));
			if (authenticationToken != null) {
				connection.setRequestProperty("Authorization", "Bearer " + authenticationToken);
			}
			if (Arrays.asList("POST", "PUT").contains(req.getMethod().toUpperCase())) {
				connection.setDoOutput(true);
				try (InputStream is = req.getInputStream(); OutputStream os = connection.getOutputStream()) {
					proxy(is, os);
				}
			}
			connection.connect();
		} catch (Exception exception) {
			throw new ProxyRequestException(exception);
		}
	}

	private void proxyResponse(HttpServletResponse res, HttpURLConnection connection) throws ProxyResponseException {
		try {
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
		} catch (Exception exception) {
			throw new ProxyResponseException(exception);
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
