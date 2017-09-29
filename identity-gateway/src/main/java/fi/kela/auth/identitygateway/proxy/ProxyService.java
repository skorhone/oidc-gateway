package fi.kela.auth.identitygateway.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import fi.kela.auth.identitygateway.util.URLs;
import fi.kela.auth.identitygateway.values.AppPropValues;

@Controller
public class ProxyService {
	private static final Logger logger = Logger.getLogger(ProxyService.class);
	@Autowired
	private AppPropValues appPropValues;

	public void proxy(HttpServletRequest req, HttpServletResponse res, String authenticationToken)
			throws ServletException, IOException {
		String target = getProxyTarget(req);
		logger.info("Proxying request to " + target);
		HttpURLConnection connection = (HttpURLConnection) new URL(target).openConnection();
		proxyRequest(req, connection, authenticationToken);
		proxyResponse(res, connection);
	}

	private String getProxyTarget(HttpServletRequest req) {
		return URLs.concatURL(appPropValues.getProxyTarget(), req.getServletPath(), req.getQueryString());
	}

	private void proxyRequest(HttpServletRequest req, HttpURLConnection connection, String authenticationToken)
			throws ProtocolException, IOException {
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
