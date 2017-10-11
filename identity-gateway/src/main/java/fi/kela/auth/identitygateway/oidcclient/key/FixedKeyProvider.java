package fi.kela.auth.identitygateway.oidcclient.key;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class FixedKeyProvider implements KeyProvider {
	private RSAPublicKey publicKey;

	public static FixedKeyProvider of(String publicKey) throws KeyException {
		try {
			KeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
			KeyFactory kf = KeyFactory.getInstance("RSA");

			FixedKeyProvider fixedKeyProvider = new FixedKeyProvider();
			fixedKeyProvider.publicKey = (RSAPublicKey) kf.generatePublic(spec);
			return fixedKeyProvider;
		} catch (Exception exception) {
			throw new KeyException("Could not create fixed key provider for configured public key " + publicKey);
		}
	}

	@Override
	public RSAPublicKey getRSAPublicKey(String kid) {
		return publicKey;
	}
}
