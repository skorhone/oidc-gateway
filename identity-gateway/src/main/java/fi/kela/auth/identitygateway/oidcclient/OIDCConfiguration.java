package fi.kela.auth.identitygateway.oidcclient;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("oidc")
public class OIDCConfiguration {
	private String issuer;
	private String loginProvider;
	private String tokenProvider;
	private String jwksProvider;
	private long jwksReloadAfter;
	private String signatureAlgorithm;
	private String secretKey;
	private String publicKey;
	private String clientId;
	private String clientSecret;

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getLoginProvider() {
		return loginProvider;
	}

	public void setLoginProvider(String loginProvider) {
		this.loginProvider = loginProvider;
	}

	public String getTokenProvider() {
		return tokenProvider;
	}

	public void setTokenProvider(String tokenProvider) {
		this.tokenProvider = tokenProvider;
	}
	
	public String getJwksProvider() {
		return jwksProvider;
	}
	
	public void setJwksProvider(String jwksProvider) {
		this.jwksProvider = jwksProvider;
	}
	
	public long getJwksReloadAfter() {
		return jwksReloadAfter;
	}
	
	public void setJwksReloadAfter(long jwksReloadAfter) {
		this.jwksReloadAfter = jwksReloadAfter;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String signingKey) {
		this.secretKey = signingKey;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
}
