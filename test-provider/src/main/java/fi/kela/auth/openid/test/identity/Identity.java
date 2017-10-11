package fi.kela.auth.openid.test.identity;

public class Identity {
	private String redirectURI;
	private String subject;
	private String name;
	private String groupId;
	private long expiresAt;

	public Identity(String redirectURI, String subject, String name, String groupId) {
		this.redirectURI = redirectURI;
		this.subject = subject;
		this.name = name;
		this.groupId = groupId;
	}

	public String getRedirectURI() {
		return redirectURI;
	}

	public String getSubject() {
		return subject;
	}

	public String getName() {
		return name;
	}

	public String getGroupId() {
		return groupId;
	}
	
	public long getExpiresAt() {
		return expiresAt;
	}
	
	public void setExpiresAt(long expiresAt) {
		this.expiresAt = expiresAt;
	}
	
	public boolean isExpired() {
		return System.currentTimeMillis() > expiresAt;
	}
}
