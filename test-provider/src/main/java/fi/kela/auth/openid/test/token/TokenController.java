package fi.kela.auth.openid.test.token;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;

import fi.kela.auth.openid.test.config.ProviderConfiguration;
import fi.kela.auth.openid.test.identity.Identity;
import fi.kela.auth.openid.test.identity.IdentityService;

@RestController
public class TokenController {
	@Autowired
	private ProviderConfiguration providerConfiguration;
	@Autowired
	private IdentityService identityService;

	@RequestMapping(value = "/token", method = RequestMethod.POST, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public Token createToken(TokenRequest request) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		if ("authorization_code".equals(request.getGrant_type())) {
			return createTokenWithAuthorizationCode(request);
		}
		if ("refresh_token".equals(request.getGrant_type())) {
			return createTokenWithRefreshToken(request);
		}
		throw new IllegalArgumentException("Unsupported grant type: " + request.getGrant_type());
	}

	private Token createTokenWithAuthorizationCode(TokenRequest request)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		Identity identity = identityService.getIdentity(request.getCode());
		return createTokenUsingIdentity(request, identity);
	}

	private Token createTokenWithRefreshToken(TokenRequest request)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		Identity identity = identityService.getIdentity(request.getRefresh_token());
		return createTokenUsingIdentity(request, identity);
	}

	private Token createTokenUsingIdentity(TokenRequest request, Identity identity)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		String refreshToken = createRefreshToken(identity);
		Instant now = Instant.now();
		Duration expiresIn = Duration.ofSeconds(providerConfiguration.getAccessTokenExpire());
		String accessToken = createAccessToken(identity, now, expiresIn);
		return new Token(null, accessToken, refreshToken, request.getGrant_type(), (int) expiresIn.getSeconds());
	}

	private String createAccessToken(Identity identity, Instant now, Duration expiresIn)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		Algorithm algorithm = getAlgorithm();
		Builder accessTokenBuilder = JWT.create().withIssuer(providerConfiguration.getIssuerName())
				.withSubject(identity.getSubject()).withClaim("name", identity.getName())
				.withArrayClaim("groupIds", new String[] { identity.getGroupId() }).withIssuedAt(Date.from(now))
				.withExpiresAt(Date.from(now.plus(expiresIn)));
		if (providerConfiguration.isAudiences()) {
			accessTokenBuilder = accessTokenBuilder.withAudience(providerConfiguration.getAudiences());
		}
		return accessTokenBuilder.sign(algorithm);
	}

	private Algorithm getAlgorithm() {
		Algorithm algorithm;
		try {
			if ("RS256".equalsIgnoreCase(providerConfiguration.getSignatureAlgorithm())) {
				algorithm = getRS256Algorithm();
			} else if ("HS256".equalsIgnoreCase(providerConfiguration.getSignatureAlgorithm())) {
				algorithm = getHS256Algorithm();
			} else {
				throw new NoSuchAlgorithmException(
						"Unsupported algorithm: " + providerConfiguration.getSignatureAlgorithm());
			}
		} catch (Exception exception) {
			throw new IllegalStateException("Could not initialize requested signing algorithm", exception);
		}
		return algorithm;
	}

	private Algorithm getRS256Algorithm() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				Base64.getDecoder().decode(providerConfiguration.getPrivateKey()));
		KeySpec publicKeySpec = new X509EncodedKeySpec(
				Base64.getDecoder().decode(providerConfiguration.getPublicKey()));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return Algorithm.RSA256((RSAPublicKey) kf.generatePublic(publicKeySpec),
				(RSAPrivateKey) kf.generatePrivate(privateKeySpec));
	}

	private Algorithm getHS256Algorithm() throws UnsupportedEncodingException {
		return Algorithm.HMAC256(providerConfiguration.getSecretKey());
	}

	private String createRefreshToken(Identity identity) {
		return identityService.storeIdentity(identity);
	}
}