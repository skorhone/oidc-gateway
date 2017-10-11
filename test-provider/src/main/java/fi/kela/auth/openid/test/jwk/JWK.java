package fi.kela.auth.openid.test.jwk;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class JWK {
	private String alg;
	private String kty;
	private String use;
	private String[] x5c;
	private String n;
	private String e;
	private String kid;

	public static JWK of(String kid, RSAPublicKey publicKey) throws JWKException {
		try {
			JWK jwk = new JWK();
			jwk.alg = "RS256";
			jwk.kty = "RSA";
			jwk.use = "SIG";
			jwk.n = encode(publicKey.getModulus().toByteArray());
			jwk.e = encode(publicKey.getPublicExponent().toByteArray());
			jwk.kid = kid;
			return jwk;
		} catch (Exception exception) {
			throw new JWKException("Could not create JWK from public key " + kid, exception);
		}
	}

	private static String encode(byte[] input) {
		return Base64.getUrlEncoder().encodeToString(input);
	}

	public String getAlg() {
		return alg;
	}

	public String getKty() {
		return kty;
	}

	public String getUse() {
		return use;
	}

	public String[] getX5c() {
		return x5c;
	}

	public String getN() {
		return n;
	}

	public String getE() {
		return e;
	}

	public String getKid() {
		return kid;
	}
}
