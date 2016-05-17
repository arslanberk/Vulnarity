package org.arslan.vulnarity.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;

public class sqliController {
		public boolean v;
		private URL url;
	    private URLConnection connection;
	    private HttpsURLConnection connectionS;
	    
	    private String[][] sqlerror={   {"MySQL","error in your SQL syntax"},
	                                    {"MiscError","mysql_fetch"},
	                                    {"MiscError2","num_rows"},
	                                    {"Oracle","ORA-01756"},
	                                    {"JDBC_CFM","Error Executing Database Query"},
	                                    {"JDBC_CFM2","SQLServer JDBC Driver"},
	                                    {"MSSQL_OLEdb","Microsoft OLE DB Provider for SQL Server"},
	                                    {"MSSQL_Uqm","Unclosed quotation mark"},
	                                    {"MS-Access_ODBC","ODBC Microsoft Access Driver"},
	                                    {"MS-Access_JETdb","Microsoft JET Database"},
	                                    {"Error Occurred While Processing Request","Error Occurred While Processing Request"},
	                                    {"Server Error","Server Error"},
	                                    {"Microsoft OLE DB Provider for ODBC Drivers error","Microsoft OLE DB Provider for ODBC Drivers error"},
	                                    {"Invalid Querystring","Invalid Querystring"},
	                                    {"OLE DB Provider for ODBC","OLE DB Provider for ODBC"},
	                                    {"VBScript Runtime","VBScript Runtime"},
	                                    {"ADODB.Field","ADODB.Field"},
	                                    {"BOF or EOF","BOF or EOF"},
	                                    {"ADODB.Command","ADODB.Command"},
	                                    {"JET Database","JET Database"},
	                                    {"mysql_fetch_array()","mysql_fetch_array()"},
	                                    {"Syntax error","Syntax error"},
	                                    {"mysql_numrows()","mysql_numrows()"},
	                                    {"GetArray()","GetArray()"},
	                                    {"FetchRow()","FetchRow()"},
	                                    {"Input string was not in a correct format","Input string was not in a correct format"}
	                                };
	    
	    private String[] params={   "\'",
	                                "%27"
	                            };
	     
	    /**
	     * Constructor for XSS controller.
	     * @param link
	     */
	    public sqliController(String link){
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
	                for(int i=0; i<sqlerror.length;i++){
	                	for(int j=0;j<sqlerror[i].length;j++){
	                        if(decodedString.contains(sqlerror[i][j])){
	                        vulnerability=true;
	                        v=true;
	                        break;
	                        }
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
	                for(int i=0; i<sqlerror.length;i++){
	                	for(int j=0;j<sqlerror[i].length;j++){
	                        if(decodedString.contains(sqlerror[i][j])){
	                        vulnerability=true;
	                        v=true;
	                        break;
	                        }
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
