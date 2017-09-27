package fi.kela.auth.identitygateway;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import org.apache.log4j.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class OpenIDClient {
	private static final String ISSUER = "https://openid.kela.fi";
	private static final String ENCODING = "utf-8";
	private static final String LOGIN_PROVIDER = "http://localhost:18080/login";
	private static final String TOKEN_PROVIDER = "http://localhost:18080/token";
	private static final String CLIENT_ID = "kela";
	private static final Logger logger = Logger.getLogger(OpenIDClient.class);

	public String getLoginProviderURL(String state, String redirectURI) throws IOException {
		return LOGIN_PROVIDER + "?response_type=code&scope=openid&client_id=" + CLIENT_ID + "&state="
				+ URLEncoder.encode(state, ENCODING) + "&redirect_uri=" + URLEncoder.encode(redirectURI, ENCODING);
	}

	public String getToken(String code, String redirectURI) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(TOKEN_PROVIDER).openConnection();
		sendTokenRequest(connection, code, redirectURI);
		String token = readTokenResponse(connection);
		if (!isValidToken(token)) {
			throw new IllegalStateException("Token is not valid");
		}
		return token;
	}

	private void sendTokenRequest(HttpURLConnection connection, String code, String redirectURI) throws IOException {
		connection.setDoOutput(true);
		connection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		connection.setRequestMethod("POST");
		connection.getOutputStream()
				.write(("grant_type=authorization_code" + "&code=" + URLEncoder.encode(code, ENCODING) + "&redirect_uri"
						+ URLEncoder.encode(redirectURI, ENCODING)).getBytes(ENCODING));
	}

	private boolean isTokenInResponse(HttpURLConnection connection) throws IOException {
		return connection.getResponseCode() == 200 && "application/json".equals(connection.getContentType());
	}

	private String readTokenResponse(HttpURLConnection connection) throws IOException {
		if (!isTokenInResponse(connection)) {
			// TODO: Fix this
			throw new IllegalStateException("No token?!");
		}
		return readResponse(connection);
	}

	private String readResponse(HttpURLConnection connection) throws IOException, UnsupportedEncodingException {
		try (InputStream is = connection.getInputStream();
				InputStreamReader isr = new InputStreamReader(is, ENCODING)) {
			char[] buf = new char[4096];
			int cnt;
			StringBuilder token = new StringBuilder();
			while ((cnt = isr.read(buf)) > 0) {
				token.append(buf, 0, cnt);
			}
			return token.toString();
		}
	}

	private boolean isValidToken(String token) {
		boolean valid = false;
		try {
			Algorithm algorithm = Algorithm.HMAC256("secret");
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(ISSUER).build();
			DecodedJWT jwt = verifier.verify(token);
			valid = true;
		} catch (UnsupportedEncodingException exception) {
			// UTF-8 encoding not supported
			logger.warn("Invalid token: " + token, exception);
		} catch (JWTVerificationException exception) {
			// Invalid signature/claims
			logger.warn("Invalid token: " + token, exception);
		}
		return valid;
	}
}