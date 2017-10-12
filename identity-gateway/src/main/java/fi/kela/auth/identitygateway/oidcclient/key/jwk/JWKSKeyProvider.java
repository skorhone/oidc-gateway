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

import org.apache.log4j.Logger;

import fi.kela.auth.identitygateway.json.JSONService;
import fi.kela.auth.identitygateway.oidcclient.key.KeyException;
import fi.kela.auth.identitygateway.oidcclient.key.KeyProvider;

public class JWKSKeyProvider implements KeyProvider {
	private static final Logger logger = Logger.getLogger(JWKSKeyProvider.class);
	private JSONService jsonService;
	private URL providerURL;
	private Map<String, PublicKey> publicKeys;
	private long keysLoadedAt;
	private long jwksReloadAfter;

	public JWKSKeyProvider(URL providerUrl, JSONService jsonService, long jwksReloadAfter) {
		this.providerURL = providerUrl;
		this.jsonService = jsonService;
		this.jwksReloadAfter = jwksReloadAfter;
		logger.info("Initialized JWKS provider. Loading keys from " + providerURL.toExternalForm() + " every "
				+ jwksReloadAfter + " milliseconds");
	}

	private JWKS loadJWKS() throws KeyException {
		try {
			return jsonService.readValue(providerURL, JWKS.class);
		} catch (Exception exception) {
			throw new KeyException("Could not load keys from " + providerURL.toExternalForm(), exception);
		}
	}

	private void loadPublicKeys() throws KeyException {
		this.publicKeys = loadJWKS().getKeys().stream().collect(Collectors.toMap(JWK::getKid, this::createPublicKey));
		updateKeysLoadedAt();
	}

	private void updateKeysLoadedAt() {
		this.keysLoadedAt = System.currentTimeMillis();
	}

	private boolean isLoadRequired() {
		return publicKeys == null;
	}

	private boolean isReloadRequired() {
		return System.currentTimeMillis() - keysLoadedAt > jwksReloadAfter;
	}

	private Map<String, PublicKey> getCurrentPublicKeys() {
		return publicKeys;
	}

	private synchronized Map<String, PublicKey> getPublicKeys() throws KeyException {
		if (isLoadRequired()) {
			loadPublicKeys();
		} else if (isReloadRequired()) {
			try {
				loadPublicKeys();
			} catch (KeyException exception) {
				logger.warn("Could not reload keys from " + providerURL.toExternalForm()
						+ ". Using previously loaded keys until next refresh", exception);
				updateKeysLoadedAt();
			}
		}
		return getCurrentPublicKeys();
	}

	@Override
	public RSAPublicKey getRSAPublicKey(String kid) throws KeyException {
		PublicKey publicKey = getPublicKeys().get(kid);
		if (!"RSA".equals(publicKey.getAlgorithm())) {
			throw new KeyException("Key " + kid + " is not RSA key");
		}
		return (RSAPublicKey) publicKey;
	}

	private PublicKey createPublicKey(JWK jwk) throws KeyException {
		try {
			BigInteger modulus = new BigInteger(Base64.getUrlDecoder().decode(jwk.getN()));
			BigInteger exponent = new BigInteger(Base64.getUrlDecoder().decode(jwk.getE()));

			RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPublicKey) keyFactory.generatePublic(spec);
		} catch (Exception exception) {
			throw new KeyException("Could not create public key from jwk with id " + jwk.getKid(), exception);
		}
	}
}