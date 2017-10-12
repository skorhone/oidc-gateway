package fi.kela.auth.identitygateway.oidcclient;

import java.io.Serializable;

public class Token implements Serializable {
	private static final long serialVersionUID = 1L;
	// JWT Access token
	private String accessToken;
	// JWT Refresh token
	private String refreshToken;
	// Time Access token expires at
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