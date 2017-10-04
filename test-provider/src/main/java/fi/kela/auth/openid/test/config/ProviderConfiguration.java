package fi.kela.auth.openid.test.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("op")
public class ProviderConfiguration {
	private String issuerName;
	private String[] audiences;
	private int accessTokenExpire;
	private int refreshTokenExpire;
	private String signatureAlgorithm;
	private String privateKey;
	private String publicKey;
	private String secretKey;

	public String getIssuerName() {
		return issuerName;
	}

	public boolean isAudiences() {
		return getAudiences().length > 0;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}

	public String[] getAudiences() {
		if (audiences == null) {
			audiences = new String[0];
		}
		return audiences;
	}

	public void setAudiences(String[] audiences) {
		this.audiences = audiences;
	}

	public int getAccessTokenExpire() {
		return accessTokenExpire;
	}

	public void setAccessTokenExpire(int accessTokenExpire) {
		this.accessTokenExpire = accessTokenExpire;
	}

	public int getRefreshTokenExpire() {
		return refreshTokenExpire;
	}

	public void setRefreshTokenExpire(int refreshTokenExpire) {
		this.refreshTokenExpire = refreshTokenExpire;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}
}
