package fi.kela.auth.identitygateway.auth;

public class AuthException extends Exception {
	private static final long serialVersionUID = 1L;

	public AuthException(Throwable cause) {
		super(cause);
	}

	public AuthException(String message, Throwable cause) {
		super(message, cause);
	}
}
