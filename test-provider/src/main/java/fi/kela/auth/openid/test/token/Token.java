package fi.kela.auth.openid.test.token;

public class Token {
	private String id_token;
	private String access_token;
	private String token_type;
	private int expires_in;

	public Token(String id_token, String access_token, String token_type, int expires_in) {
		this.id_token = id_token;
		this.access_token = access_token;
		this.token_type = token_type;
		this.expires_in = expires_in;
	}

	public String getId_token() {
		return id_token;
	}

	public String getAccess_token() {
		return access_token;
	}

	public String getToken_type() {
		return token_type;
	}

	public int getExpires_in() {
		return expires_in;
	}
}
