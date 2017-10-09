package fi.kela.auth.identitygateway.proxy;

public class ProxyResponseException extends Exception {
	private static final long serialVersionUID = 1L;

	public ProxyResponseException(Throwable cause) {
		super(cause);
	}
}
