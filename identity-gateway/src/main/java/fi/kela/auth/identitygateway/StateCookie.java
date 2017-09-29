package fi.kela.auth.identitygateway;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import fi.kela.auth.identitygateway.config.AppConstants;

public class StateCookie {
	private String state;
	private String origin;

	public StateCookie(String state, String origin) {
		this.state = state;
		this.origin = origin;
	}

	public String getState() {
		return state;
	}

	public String getOrigin() {
		return origin;
	}

	public static StateCookie of(String encoded) {
		if (encoded == null) {
			return null;
		}
		int andAt = encoded.indexOf('&');
		if (andAt < 0) {
			throw new IllegalArgumentException("Unexpected state cookie content: " + encoded);
		}
		try {
			String state = URLDecoder.decode(encoded.substring(0, andAt), AppConstants.ENCODING);
			String origin = URLDecoder.decode(encoded.substring(andAt + 1), AppConstants.ENCODING);
			return new StateCookie(state, origin);
		} catch (IOException exception) {
			throw new IllegalStateException("Could not decode state cookie: " + encoded, exception);
		}
	}

	@Override
	public String toString() {
		try {
			return URLEncoder.encode(state, AppConstants.ENCODING) + "&"
					+ URLEncoder.encode(origin, AppConstants.ENCODING);
		} catch (IOException exception) {
			throw new IllegalStateException("Could not encode state cookie", exception);
		}
	}
}
