package fi.kela.auth.identitygateway.oidcclient;

public class Token {
	private String accessToken;
	private String refreshToken;
	private long expiresAt;

	public Token(String accessToken, String refreshToken, long expiresAt) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.expiresAt = expiresAt;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public long getExpiresAt() {
		return expiresAt;
	}
}
