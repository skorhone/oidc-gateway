package fi.kela.auth.openid.test.token;

public class UnsupportedGrantTypeException extends Exception {
	private static final long serialVersionUID = 1L;
	
	public UnsupportedGrantTypeException(String message) {
		super(message);
	}
}
