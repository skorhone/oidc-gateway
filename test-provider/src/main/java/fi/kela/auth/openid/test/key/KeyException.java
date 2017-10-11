package fi.kela.auth.openid.test.key;

public class KeyException extends Exception {
	private static final long serialVersionUID = 1L;

	public KeyException(String message, Throwable cause) {
		super(message, cause);
	}

	public KeyException(String message) {
		super(message);
	}
}
