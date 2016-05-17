package org.arslan.vulnarity.controller;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

public class connectionController {
	
	    private URL url;
	    private URLConnection connection;
	    private HttpsURLConnection connectionS;
	    private String status;
	    private String server;
	    private String contenttype;
	    private long expiration;
	    private long length;
	    private String cipherSuite;
	    private Certificate[] certs;
	    
	    /**
	     * Constructor for HTTP connections. Connection type is URLConnection.
	     * @param targetUrl
	     */
	    public connectionController(String targetUrl) {  
	            try { 
	                url= new URL(targetUrl);
	                connection = url.openConnection();
	                connection.setDoOutput(true);	
	            } 
	            catch (MalformedURLException ex) {} 
	            catch (IOException ex) { } 
	            catch (Exception ex) {}
	        
	    }
	    
	    /**
	     * Constructor for HTTPS connections. Value of t is not important in this version.
	     * Connection type is HttpsURLConnection.
	     * @param targetUrl
	     * @param t
	     */
	    public connectionController(String targetUrl, boolean t) {  
	        try { 
                //System.out.print(targetUrl);
                url= new URL(targetUrl);
                connectionS = (HttpsURLConnection)url.openConnection();
                connectionS.setDoOutput(true);
            } 
            catch (MalformedURLException ex) {} 
            catch (IOException ex) { } 
            catch (Exception ex) {}      
	    }
	    
	    /**
	     * Static method.
	     * Checks if URL does not throw MalformedURLException or URISyntaxException.
	     * @param url
	     * @return boolean: true if URL is valid, or false if URL is invalid.
	     * @throws Exception
	     */
	    public static boolean isValidURL(String url) throws Exception {  
	    	URL u = null;
	        try {  
	            u = new URL(url);  
	        } catch (MalformedURLException e) {  
	            return false;  
	        }
	        try {  
	            u.toURI();  
	        } catch (URISyntaxException e) {  
	            return false;  
	        }  
	        return true;  
	    } 
	    
	   /**
	    * Static method.
	    * @return boolean: true if URL contains $Vparam, or false if URL does not contain $Vparam.
	    */
	    public static boolean isVparam(String url){
	    	if(url.contains("$Vparam"))
            {
	    		return true;
            }
	    	else{
	    		return false;
	    	}
	    }
	    
	    /**
	     * Static method.
	     * @param url
	     * @return boolean: true if URL contains http://, or false.
	     */
	    public static boolean isHTTP(String url){
	    	if(url.contains("http://")||url.contains("HTTP://"))
            {
	    		return true;
            }
	    	else{
	    		return false;
	    	}
	    }
	    
	    /**
	     * Static method.
	     * @param url
	     * @return boolean: true if URL contains https://, or false.
	     */
	    public static boolean isHTTPS(String url){
	    	if(url.contains("https://")||url.contains("HTTPS://"))
            {
	    		return true;
            }
	    	else{
	    		return false;
	    	}
	    }
	    
	    /**
	     * This method is only for HTTP connections.
	     * @return String: Response code.
	     */
        public String getStatus(){
	        status = connection.getHeaderField(null);   
	        return status;
	    }
        
        /**
	     * This method is only for HTTPS connections.
	     * @return String: Response code.
	     */
        public String getStatusS(){
	        try {
				status = Integer.toString(connectionS.getResponseCode());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}  
	        return status;
	    }
        
        /**
         * This method is only for HTTP connections.
         * @return String: Server Type.
         */
	    public String getServer() {
	        server = connection.getHeaderField("Server");
	        return server;
	    }
	  
	    /**
	     * This method is only for HTTPS connections.
         * @return String: Server type.
         */
	    public String getServerS() {
	        server = connectionS.getHeaderField("Server");
	        return server;
	    }
	    
	    /**
	     * This method is only for HTTP connections.
	     * @return String: Content type.
	     */
	    public String getContentType() {
	        contenttype = connection.getHeaderField("Content-Type");
	        return contenttype;
	    }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return String: Content type.
	     */
	    public String getContentTypeS() {
	        contenttype = connectionS.getHeaderField("Content-Type");
	        return contenttype;
	    }
	  
	    /**
	     * This method is only for HTTP connections.
	     * @return long: Expiration.
	     */
	    public long getExpiration() {
	        expiration = connection.getExpiration();
	        return expiration;
	    }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return long: Expiration.
	     */
	    public long getExpirationS() {
	        expiration = connectionS.getExpiration();
	        return expiration;
	    }
	   
	    /**
	     * This method is only for HTTP connections.
	     * @return long: Length.
	     */
	    public long getLength() {
	        length = connection.getContentLengthLong();
	        return length;
	    }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return long: Length.
	     */
	    public long getLengthS() {
	        length = connectionS.getContentLengthLong();
	        return length;
	    }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return String: Cipher Suite.
	     */
	    public String getCipherSuiteS(){
	    	cipherSuite  = connectionS.getCipherSuite();
	    	return cipherSuite;
	    }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return array : Certificate[] certifications.
	     */
	    public Certificate[] getCertificatesS(){
	    	try {
				certs  = connectionS.getServerCertificates();
			} catch (SSLPeerUnverifiedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	return certs;
	    }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return int: count of certificates.
	     */
	    public int getCountCertificatesS(){
	    	Certificate[] c = getCertificatesS();
	    	int count = c.length;
	    	return count;
	    }
	    
	    public void closeConnection(){
	    	
	    }
}
