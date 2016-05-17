package org.arslan.vulnarity.model;

public class informationModel {
	
	private String initialURL;
	private String server;
	private String status;
	private String contentType;
	private String Length;
	private String Expiration;
	private String cipherSuite;
	
	public String getInitialURL() {
		return initialURL;
	}
	public void setInitialURL(String initialURL) {
		this.initialURL = initialURL;
	}
	public String getServer() {
		return server;
	}
	public void setServer(String server) {
		this.server = server;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public String getContentType() {
		return contentType;
	}
	public void setContentType(String contentType) {
		this.contentType = contentType;
	}
	public String getLength() {
		return Length;
	}
	public void setLength(String length) {
		Length = length;
	}
	public String getExpiration() {
		return Expiration;
	}
	public void setExpiration(String expiration) {
		Expiration = expiration;
	}
	public String getCipherSuite() {
		return cipherSuite;
	}
	public void setCipherSuite(String cipherSuite) {
		this.cipherSuite = cipherSuite;
	}
	
	
}
