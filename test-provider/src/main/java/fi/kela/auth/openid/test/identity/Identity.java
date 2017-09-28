package fi.kela.auth.openid.test.identity;

public class Identity {
	private String redirectURI;
	private String subject;
	private String name;
	private String groupId;

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
}
