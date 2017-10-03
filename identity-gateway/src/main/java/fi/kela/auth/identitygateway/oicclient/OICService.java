package fi.kela.auth.identitygateway.oicclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.stereotype.Controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import fi.kela.auth.identitygateway.config.AppConstants;
import fi.kela.auth.identitygateway.config.IGWConfiguration;
import fi.kela.auth.identitygateway.util.URLs;

/**
 * OpenID Connect service
 *
 */
@Controller
public class OICService {
	private static final Logger logger = Logger.getLogger(OICService.class);
	@Autowired
	private IGWConfiguration appPropValues;

	public String getLoginProviderURL(String state, String redirectURI) throws IOException {
		return URLs.concatURL(appPropValues.getOic().getLoginProvider(), "",
				"response_type=code&scope=openid&client_id="
						+ URLEncoder.encode(appPropValues.getOic().getClientId(), AppConstants.ENCODING) + "&state="
						+ URLEncoder.encode(state, AppConstants.ENCODING) + "&redirect_uri="
						+ URLEncoder.encode(redirectURI, AppConstants.ENCODING));
	}

	public Token getTokenWithRefreshToken(String refreshToken) throws IOException {
		throw new IllegalStateException("Not yet implemented");
	}

	public Token getTokenWithAuthorizationCode(String code, String redirectURI) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(appPropValues.getOic().getTokenProvider())
				.openConnection();
		sendTokenRequest(connection, code, redirectURI);
		Token token = readTokenResponse(connection);
		if (!isValidToken(token)) {
			throw new IllegalStateException("Token is not valid");
		}
		return token;
	}

	private void logTokenError(HttpURLConnection connection) throws IOException {
		try (InputStream is = connection.getResponseCode() > 200 ? connection.getErrorStream()
				: connection.getInputStream()) {
			String response = readResponse(is);
			logger.error("Received error while obtaining token. Connection rc: " + connection.getResponseCode()
					+ " Response: " + response);
		}
	}

	private void sendTokenRequest(HttpURLConnection connection, String code, String redirectURI) throws IOException {
		connection.setDoOutput(true);
		connection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		connection.setRequestMethod("POST");
		String tokenRequest = "grant_type=authorization_code&code=" + URLEncoder.encode(code, AppConstants.ENCODING)
				+ "&redirect_uri=" + URLEncoder.encode(redirectURI, AppConstants.ENCODING) + "&client_id="
				+ URLEncoder.encode(appPropValues.getOic().getClientId(), AppConstants.ENCODING);
		if (appPropValues.getOic().getClientSecret() != null) {
			tokenRequest += "&client_secret="
					+ URLEncoder.encode(appPropValues.getOic().getClientSecret(), AppConstants.ENCODING);
		}
		logger.debug("Token request: " + tokenRequest);
		connection.getOutputStream().write(tokenRequest.getBytes(AppConstants.ENCODING));
	}

	private boolean isTokenInResponse(HttpURLConnection connection) throws IOException {
		String contentType = connection.getContentType();
		return connection.getResponseCode() == 200 && contentType != null && contentType.startsWith("application/json");
	}

	private Token readTokenResponse(HttpURLConnection connection) throws IOException {
		if (!isTokenInResponse(connection)) {
			logTokenError(connection);
			throw new IllegalStateException("No token?!");
		}
		return readResponse(connection);
	}

	private Token readResponse(HttpURLConnection connection) throws IOException, UnsupportedEncodingException {
		String response;
		try (InputStream is = connection.getInputStream()) {
			response = readResponse(is);
		}
		BasicJsonParser parser = new BasicJsonParser();
		Map<String, Object> token = parser.parseMap(response);

		String idToken = token.get("id_token").toString();
		String accessToken = token.get("access_token").toString();
		String tokenType = token.get("token_type").toString();
		int expiresIn = ((Number) token.get("expires_in")).intValue();
		return new Token(idToken, accessToken, tokenType, expiresIn);
	}

	private String readResponse(InputStream is) throws IOException, UnsupportedEncodingException {
		String response;
		try (InputStreamReader isr = new InputStreamReader(is, AppConstants.ENCODING)) {
			StringBuilder responseBuilder = new StringBuilder();
			char[] buf = new char[4096];
			int cnt;
			while ((cnt = isr.read(buf)) > 0) {
				responseBuilder.append(buf, 0, cnt);
			}
			response = responseBuilder.toString();
		}
		return response;
	}

	private boolean isValidToken(Token token) {
		boolean valid = false;
		try {
			Algorithm algorithm;
			if ("RS256".equalsIgnoreCase(appPropValues.getOic().getSignatureAlgorithm())) {
				KeySpec spec = new X509EncodedKeySpec(
						Base64.getDecoder().decode(appPropValues.getOic().getPublicKey()));
				KeyFactory kf = KeyFactory.getInstance("RSA");
				algorithm = Algorithm.RSA256((RSAPublicKey) kf.generatePublic(spec), null);
			} else {
				algorithm = Algorithm.HMAC256(appPropValues.getOic().getSecretKey());
			}
			Verification verification = JWT.require(algorithm);
			if (appPropValues.getOic().getIssuer() != null) {
				verification = verification.withIssuer(appPropValues.getOic().getIssuer());
			}
			JWTVerifier verifier = verification.build();
			DecodedJWT jwt = verifier.verify(token.getId_token());
			valid = true;
		} catch (Exception exception) {
			// Invalid signature/claims
			logger.warn("Invalid token: " + token, exception);
		}
		return valid;
	}
}