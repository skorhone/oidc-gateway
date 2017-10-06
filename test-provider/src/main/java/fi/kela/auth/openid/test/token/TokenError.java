package fi.kela.auth.openid.test.token;

public class TokenError {
	private String error_description;
	private String error;
	
	public TokenError(String error_description, String error) {
		this.error_description = error_description;
		this.error = error;
	}
}