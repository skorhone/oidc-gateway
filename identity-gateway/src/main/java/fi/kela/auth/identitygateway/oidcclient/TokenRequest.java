package fi.kela.auth.identitygateway.oidcclient;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import fi.kela.auth.identitygateway.util.AppConstants;

public abstract class TokenRequest {
	protected String client_id;
	protected String client_secret;
	protected String grant_type;

	public static TokenRequest createWithCode(String clientId, String clientSecret, String redirectURI, String code) {
		CodeTokenRequest tokenRequest = new CodeTokenRequest();
		tokenRequest.client_id = clientId;
		tokenRequest.client_secret = clientSecret;
		tokenRequest.redirect_uri = redirectURI;
		tokenRequest.code = code;
		return tokenRequest;
	}

	public static TokenRequest createWithRefreshToken(String clientId, String clientSecret, String refreshToken) {
		RefreshTokenRequest tokenRequest = new RefreshTokenRequest();
		tokenRequest.client_id = clientId;
		tokenRequest.client_secret = clientSecret;
		tokenRequest.refresh_token = refreshToken;
		return tokenRequest;
	}

	public abstract String toFormEncoded() throws UnsupportedEncodingException;

	public static class CodeTokenRequest extends TokenRequest {
		protected String redirect_uri;
		protected String code;

		@Override
		public String toFormEncoded() throws UnsupportedEncodingException {
			String formEncoded = "grant_type=authorization_code&code=" + URLEncoder.encode(code, AppConstants.ENCODING)
					+ "&redirect_uri=" + URLEncoder.encode(redirect_uri, AppConstants.ENCODING) + "&client_id="
					+ URLEncoder.encode(client_id, AppConstants.ENCODING);
			if (client_secret != null) {
				formEncoded += "&client_secret=" + URLEncoder.encode(client_secret, AppConstants.ENCODING);
			}
			return formEncoded;
		}
	}

	public static class RefreshTokenRequest extends TokenRequest {
		private String refresh_token;

		@Override
		public String toFormEncoded() throws UnsupportedEncodingException {
			String formEncoded = "grant_type=refresh_token&refresh_token="
					+ URLEncoder.encode(refresh_token, AppConstants.ENCODING) + "&client_id="
					+ URLEncoder.encode(client_id, AppConstants.ENCODING);
			if (client_secret != null) {
				formEncoded += "&client_secret=" + URLEncoder.encode(client_secret, AppConstants.ENCODING);
			}
			return formEncoded;
		}
	}
}
