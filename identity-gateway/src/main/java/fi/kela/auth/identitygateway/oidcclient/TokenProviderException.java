package fi.kela.auth.identitygateway.oidcclient;

public class TokenProviderException extends Exception {
	private static final long serialVersionUID = 1L;

	public TokenProviderException(Throwable cause) {
		super(cause);
	}
}
