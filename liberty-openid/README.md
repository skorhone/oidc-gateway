# liberty-openid
Websphere Liberty configuration example for receiving tokens from proxy. Configuration is located in two files: server.xml and ibm-application-bnd.xml

## server.xml
Example requires openidConnectClient-1.0 and ssl-1.0 features (or equivalent) and small configuration fragment for openIdConnectClient

    <openidConnectClient audiences="https://example.org" groupIdentifier="groupIds" realmName="example" id="RS" inboundPropagation="required" issuerIdentifier="https://openid.example.org" sharedKey="secret" signatureAlgorithm="HS256" uniqueUserIdentifier="sub"/>


## ibm-application-bnd.xml
This file is used to bind propagated groups to security roles on server. Note that access-id is mandatory and includes the realm name (format is: group:realm/groupName). File is located in webapp/META-INF

    <?xml version="1.0" encoding="UTF-8"?>
    <application-bnd xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	    xmlns="http://websphere.ibm.com/xml/ns/javaee"
	    xsi:schemaLocation="http://websphere.ibm.com/xml/ns/javaee http://websphere.ibm.com/xml/ns/javaee/ibm-application-bnd_1_0.xsd"
	    version="1.0">
	    <security-role name="customer">
		    <group name="customer" access-id="group:example/customer"/>
	    </security-role>
    </application-bnd>