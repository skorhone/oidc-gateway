package fi.kela.auth.identitygateway.util;

public class URLs {
	public static String concatURL(String base, String path) {
		return concatURL(base, path, null);
	}

	public static String concatURL(String base, String path, String queryString) {
		StringBuilder url = new StringBuilder(base);
		if (!base.endsWith("/")) {
			url.append('/');
		}
		if (path.startsWith("/")) {
			url.append(path, 1, path.length());
		} else {
			url.append(path);
		}
		if (queryString != null) {
			url.append('?').append(queryString);
		}
		return url.toString();
	}
}
