package fi.kela.auth.identitygateway.oidcclient;

public class TokenNotValidException extends Exception {
	private static final long serialVersionUID = 1L;
	
	public TokenNotValidException(Throwable cause) {
		super(cause);
	}
}
