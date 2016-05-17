package org.arslan.vulnarity.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;

public class xssController {
		public boolean v;
		private URL url;
	    private URLConnection connection;
	    private HttpsURLConnection connectionS;
	    private String[] XSSresult= {"VulnarityXSS"};
	    private String[] params={   "<script>alert(\"VulnarityXSS\");</script>",
	                                "%3Cscript%3Ealert(%5C%22VulnarityXSS%5C%22)%3B%3C%2Fscript%3E"
	                            };
	     
	    /**
	     * Constructor for XSS controller.
	     * @param link
	     */
	    public xssController(String link){
	        	try {
					url= new URL(link);
					v=false;
				} catch (MalformedURLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	    }
	    
	    /**
	     * This method is only for HTTP connections.
	     * @return String: Script which can be used to inject scripts.
	     * @throws Exception
	     */
	    public String scan() throws Exception{
	            String result="";	          
	                String test =url.toString();
	                for(int i=0;i<params.length;i++){
	                    test=test.replace("$Vparam",params[i]);
	                    connect(test);
	                    if(injectionCheck()){
	                        result=params[i];
	                        break;
	                    }
	                    else{
	                        result="N/A";
	                    }
	                }
	           
	   return result;
	   }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return String: Script which can be used to inject scripts.
	     * @throws Exception
	     */
	    public String scanS() throws Exception{
	            String result="";	          
	                String test =url.toString();
	                for(int i=0;i<params.length;i++){
	                    test=test.replace("$Vparam",params[i]);
	                    connectS(test);
	                    if(injectionCheckS()){
	                        result=params[i];
	                        break;
	                    }
	                    else{
	                        result="N/A";
	                    }
	                }
	           
	   return result;
	   }
	    
	    /**
	     * This method is only for HTTP connections.
	     * @param link
	     * @throws Exception
	     */     
	   private void connect(String link) throws Exception{
	              try { 
			            url= new URL(link);
			            connection = url.openConnection();
			            connection.setDoOutput(true);
		            } catch (MalformedURLException ex) {
		               
		            } catch (IOException ex) {
		                
	            }
	   }
	        
	   /**
	     * This method is only for HTTPS connections.
	     * @param link
	     * @throws Exception
	     */
	    private void connectS(String link) throws Exception{
	          	try { 		
	          		url= new URL(link);
		            connectionS = (HttpsURLConnection)url.openConnection();
		            connectionS.setDoOutput(true);
	            }
	          	catch (MalformedURLException ex) {}
	          	catch (IOException ex) { }
	    }
	   
	    /**
	     * This method is only for HTTP connections.
	     * @return boolean: true if vulnerability is found, or false.
	     * @throws Exception
	     */
	    private boolean injectionCheck()throws Exception{
	            boolean vulnerability=false;
	            try{
	            BufferedReader in = new BufferedReader(
	                                        new InputStreamReader(
	                                        connection.getInputStream()));
	            String decodedString;
	            while ((decodedString = in.readLine()) != null) {
	                for(int i=0; i<XSSresult.length;i++){
	                        if(decodedString.contains(XSSresult[i])){
	                        vulnerability=true;
	                        v=true;
	                        break;
	                        }
	                }
	            }
	            in.close();  
	            }
	            catch(Exception ex)
	            {
	            
	            }
	            return vulnerability;
	   }
	    
	    /**
	     * This method is only for HTTPS connections.
	     * @return boolean: true if vulnerability is found, or false.
	     * @throws Exception
	     */
	    private boolean injectionCheckS()throws Exception{
	            boolean vulnerability=false;
	            try{
	            BufferedReader in = new BufferedReader(
	                                        new InputStreamReader(
	                                        connectionS.getInputStream()));
	            String decodedString;
	            while ((decodedString = in.readLine()) != null) {
	                for(int i=0; i<XSSresult.length;i++){
	                        if(decodedString.contains(XSSresult[i])){
	                        vulnerability=true;
	                        v=true;
	                        break;
	                        }
	                }
	            }
	            in.close();  
	            }
	            catch(Exception ex)
	            {
	            
	            }
	            return vulnerability;
	   }
}
