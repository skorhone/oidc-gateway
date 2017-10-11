package fi.kela.auth.identitygateway.oidcclient.key;

public class KeyException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public KeyException(String message) {
		super(message);
	}

	public KeyException(String message, Throwable cause) {
		super(message, cause);
	}
}
