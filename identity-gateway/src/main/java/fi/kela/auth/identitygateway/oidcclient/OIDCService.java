package fi.kela.auth.identitygateway.oidcclient;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
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
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

import fi.kela.auth.identitygateway.AppConstants;
import fi.kela.auth.identitygateway.token.Token;
import fi.kela.auth.identitygateway.util.URLs;

/**
 * OpenID Connect service
 *
 */
@Service
public class OIDCService {
	private static final Logger logger = Logger.getLogger(OIDCService.class);
	@Autowired
	private OIDCConfiguration oidcConfiguration;

	public String getLoginProviderURL(String state, String redirectURI) throws IOException {
		return URLs.concatURL(oidcConfiguration.getLoginProvider(), "",
				"response_type=code&scope=openid&client_id="
						+ URLEncoder.encode(oidcConfiguration.getClientId(), AppConstants.ENCODING) + "&state="
						+ URLEncoder.encode(state, AppConstants.ENCODING) + "&redirect_uri="
						+ URLEncoder.encode(redirectURI, AppConstants.ENCODING));
	}

	public Token getTokenWithRefreshToken(String refreshToken) throws IOException, TokenNotFoundException, TokenNotValidException {
		HttpURLConnection connection = getTokenEndpointConnection();
		TokenRequest tokenRequest = TokenRequest.createWithRefreshToken(oidcConfiguration.getClientId(),
				oidcConfiguration.getClientSecret(), refreshToken);
		sendTokenRequest(connection, tokenRequest);
		return readTokenResponse(connection);
	}

	public Token getTokenWithAuthorizationCode(String code, String redirectURI) throws IOException, TokenNotFoundException, TokenNotValidException {
		HttpURLConnection connection = getTokenEndpointConnection();
		TokenRequest tokenRequest = TokenRequest.createWithCode(oidcConfiguration.getClientId(),
				oidcConfiguration.getClientSecret(), redirectURI, code);
		sendTokenRequest(connection, tokenRequest);
		return readTokenResponse(connection);
	}

	private HttpURLConnection getTokenEndpointConnection() throws IOException, MalformedURLException {
		HttpURLConnection connection = (HttpURLConnection) new URL(oidcConfiguration.getTokenProvider())
				.openConnection();
		return connection;
	}

	private void logTokenError(HttpURLConnection connection) throws IOException {
		try (InputStream is = connection.getResponseCode() > 200 ? connection.getErrorStream()
				: connection.getInputStream()) {
			String response = readResponse(is);
			logger.error("Received error while obtaining token. Connection rc: " + connection.getResponseCode()
					+ " Response: " + response);
		}
	}

	private void sendTokenRequest(HttpURLConnection connection, TokenRequest tokenRequest) throws IOException {
		connection.setDoOutput(true);
		connection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		connection.setRequestMethod("POST");
		String form = tokenRequest.toFormEncoded();
		logger.debug("Token request: " + form);
		connection.getOutputStream().write(form.getBytes(AppConstants.ENCODING));
	}

	private boolean isTokenInResponse(HttpURLConnection connection) throws IOException {
		String contentType = connection.getContentType();
		return connection.getResponseCode() == 200 && contentType != null && contentType.startsWith("application/json");
	}

	private Token readTokenResponse(HttpURLConnection connection) throws IOException, TokenNotFoundException, TokenNotValidException {
		if (!isTokenInResponse(connection)) {
			logTokenError(connection);
			throw new TokenNotFoundException();
		}
		Token token = readResponse(connection);
		validateToken(token);
		return token;
	}

	private Token readResponse(HttpURLConnection connection) throws IOException, UnsupportedEncodingException {
		String response;
		try (InputStream is = connection.getInputStream()) {
			response = readResponse(is);
		}
		BasicJsonParser parser = new BasicJsonParser();
		Map<String, Object> token = parser.parseMap(response);

		String accessToken = token.get("access_token").toString();
		String refreshToken = token.get("refresh_token").toString();
		int expiresIn = ((Number) token.get("expires_in")).intValue();
		return new Token(accessToken, refreshToken, System.currentTimeMillis() + (expiresIn * 1000));
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

	private void validateToken(Token token) throws TokenNotValidException {
		try {
			Algorithm algorithm;
			if ("RS256".equalsIgnoreCase(oidcConfiguration.getSignatureAlgorithm())) {
				KeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(oidcConfiguration.getPublicKey()));
				KeyFactory kf = KeyFactory.getInstance("RSA");
				algorithm = Algorithm.RSA256((RSAPublicKey) kf.generatePublic(spec), null);
			} else {
				algorithm = Algorithm.HMAC256(oidcConfiguration.getSecretKey());
			}
			Verification verification = JWT.require(algorithm);
			if (oidcConfiguration.getIssuer() != null) {
				verification = verification.withIssuer(oidcConfiguration.getIssuer());
			}
			JWTVerifier verifier = verification.build();
			DecodedJWT jwt = verifier.verify(token.getAccessToken());
		} catch (Exception exception) {
			throw new TokenNotValidException(exception);
		}
	}
}