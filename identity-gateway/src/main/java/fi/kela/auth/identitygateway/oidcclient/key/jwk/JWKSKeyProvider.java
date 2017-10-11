package fi.kela.auth.identitygateway.oidcclient.key.jwk;

import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import fi.kela.auth.identitygateway.oidcclient.key.KeyException;
import fi.kela.auth.identitygateway.oidcclient.key.KeyProvider;

public class JWKSKeyProvider implements KeyProvider {
	private static final ObjectReader READER = new ObjectMapper().reader();
	private String url;

	public JWKSKeyProvider(String url) {
		this.url = url;
	}

	protected JWKS getJWKS() {
		// TODO: We should warn about insecure access (no https)
		try {
			return READER.forType(JWKS.class).readValue(new URL(url));
		} catch (Exception exception) {
			// TODO: Fix this
			throw new IllegalStateException("TODO!", exception);
		}
	}

	protected Map<String, PublicKey> getPublicKeys() {
		// TODO: We should implement caching...
		return getJWKS().getKeys().stream().collect(Collectors.toMap(JWK::getKid, this::createPublicKey));
	}

	@Override
	public RSAPublicKey getRSAPublicKey(String kid) throws KeyException {
		PublicKey publicKey = getPublicKeys().get(kid);
		if (!"RSA".equals(publicKey.getAlgorithm())) {
			throw new KeyException("Key " + kid + " is not RSA key");
		}
		return (RSAPublicKey)publicKey;
	}

	private PublicKey createPublicKey(JWK jwk) throws KeyException {
		try {
			BigInteger modulus = new BigInteger(new String(Base64.getUrlDecoder().decode(jwk.getN()), "utf-8"));
			BigInteger exponent = new BigInteger(new String(Base64.getUrlDecoder().decode(jwk.getE()), "utf-8"));

			RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPublicKey)keyFactory.generatePublic(spec);
		} catch (Exception exception) {
			throw new KeyException("Could not create public key from jwk with id " + jwk.getKid(), exception);
		}
	}
}