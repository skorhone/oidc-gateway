package fi.kela.auth.identitygateway.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ExecutorService;

import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import fi.kela.auth.identitygateway.IGWConfiguration;
import fi.kela.auth.identitygateway.util.URLs;

@Service
public class ProxyService {
	private static final Logger logger = Logger.getLogger(ProxyService.class);
	private IGWConfiguration appPropValues;
	private ExecutorService executorService;

	public ProxyService(IGWConfiguration appPropValues, ExecutorService executorService) {
		this.appPropValues = appPropValues;
		this.executorService = executorService;
	}

	public void proxy(HttpServletRequest req, HttpServletResponse res, String authenticationToken)
			throws ServletException, IOException {
		AsyncContext context = req.startAsync();
		Runnable runnable = () -> {
			String target = getProxyTarget(req);
			logger.info("Proxying request to " + target);
			try {
				HttpURLConnection connection = openConnection(target);
				proxyRequest(req, connection, authenticationToken);
				proxyResponse(res, connection);
			} catch (ProxyResponseException exception) {
				logger.warn("Exception occured while proxying response to client", exception);
			} catch (ProxyRequestException exception) {
				logger.warn("Exception occured while proxying request to backend", exception);
				handleBackendError(res);
			} catch (OpenConnectionException exception) {
				logger.warn("Exception occured while connecting to backend", exception);
				handleBackendError(res);
			}
			context.complete();
		};
		executorService.submit(runnable);
	}

	private void handleBackendError(HttpServletResponse res) {
		try {
			res.sendError(HttpStatus.SERVICE_UNAVAILABLE.value());
		} catch (Exception exception) {
		}
	}

	private HttpURLConnection openConnection(String target) throws OpenConnectionException {
		try {
			return (HttpURLConnection) new URL(target).openConnection();
		} catch (Exception exception) {
			throw new OpenConnectionException(exception);
		}
	}

	private String getProxyTarget(HttpServletRequest req) {
		return URLs.concatURL(appPropValues.getProxyTarget(), req.getServletPath(), req.getQueryString());
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
