package org.arslan.vulnarity.controller;

import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.SingleSelectionModel;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.stage.Stage;
import org.arslan.vulnarity.model.informationModel;
import org.arslan.vulnarity.model.sqliModel;
import org.arslan.vulnarity.model.xssModel;
import org.arslan.vulnarity.view.confirmBox;
import org.arslan.vulnarity.view.alertBox;

public class mainController implements Initializable{
	
	public MenuItem menuItemSaveResult;
	public Button startScanButton;
	public Button certificateDetails;
	public ToggleButton informationOption;
	public ToggleButton SQLIOption;
	public ToggleButton XSSOption;
	public TextField urlParameter;
	public TabPane TRtab;
	public Label error;
	public Label rInitURL;
	public Label rServer;
	public Label rStatus;
	public Label rContentType;
	public Label rLength;
	public Label rExpiration;

	public Label SQLIV;
	public Label SQLIParameter;
	public Label SQLIUsage;
	
	public Label XSSV;
	public Label XSSParameter;
	public Label XSSUsage;
	
	public Label cipherSuiteLabel;
	public Label cipherSuite;
        
        public ComboBox AV;
        public ComboBox AC;
        public ComboBox PR;
        public ComboBox UI;
        public ComboBox CI;
        public ComboBox II;
        public ComboBox AI;
        public ComboBox CR;
        public ComboBox IR;
        public ComboBox AR;
        public ComboBox S;
	
        public Label baseScore;
        public Label modifiedScore;
        public TextArea metricDescription;
        
        public Button calculateButton;
	
	public void startScanButtonClicked(){
		boolean result=false;
		try {
			cipherSuiteLabel.setVisible(false);
			cipherSuite.setVisible(false);	
			rInitURL.setText("");
			rServer.setText("");
			rStatus.setText("");
			rContentType.setText("");
			rLength.setText("");
			rExpiration.setText("");
			cipherSuite.setText("");
			SQLIV.setText("");
			SQLIUsage.setText("");
			SQLIParameter.setText("");
			XSSV.setText("");
			XSSParameter.setText("");
			XSSUsage.setText("");
			
			if(informationOption.isSelected()){ //Check if information is selected.	
				if(connectionController.isValidURL(urlParameter.getText()) && !urlParameter.getText().equals("")){//Check if given URL is valid.
					if(connectionController.isHTTP(urlParameter.getText())){//Check if given URL is HTTP type.
						//INFORMATION for HTTP
						result = true;
						error.setText("");
						cipherSuiteLabel.setVisible(false);
						cipherSuite.setVisible(false);	
						connectionController reader=new connectionController(urlParameter.getText());
						rInitURL.setText(urlParameter.getText());
						rServer.setText(reader.getServer());
						rStatus.setText(reader.getStatus());
						rContentType.setText(reader.getContentType());
						rLength.setText(Long.toString(reader.getLength()));
						rExpiration.setText(Long.toString(reader.getExpiration()));
					}
					else if(connectionController.isHTTPS(urlParameter.getText())){//Check if given URL is HTTPS type.
						//INFORMATION for HTTPS
						result = true;
						error.setText("");
						cipherSuiteLabel.setVisible(true);
						cipherSuite.setVisible(true);	
						connectionController reader = new connectionController(urlParameter.getText(),true);
						rInitURL.setText(urlParameter.getText());
						rServer.setText(reader.getServerS());
						rStatus.setText(reader.getStatusS());
						rContentType.setText(reader.getContentTypeS());
						rLength.setText(Long.toString(reader.getLengthS()));
						rExpiration.setText(Long.toString(reader.getExpirationS()));
						cipherSuite.setText(reader.getCipherSuiteS());
					}
					else{
						error.setText("URL is not HTTP/HTTPS");
						result = false;
					}
				}
				else{
					error.setText("URL is not valid !");
					result = false;
				}
			}
			
			if(SQLIOption.isSelected()){ //Check if SQLI is selected.
				if(connectionController.isValidURL(urlParameter.getText()) && !urlParameter.getText().equals("")){//Check if given URL is valid.
					if(connectionController.isVparam(urlParameter.getText())){//Check if given URL contains $Vparam.
						if(connectionController.isHTTP(urlParameter.getText())){//Check if given URL is HTTP type.
							//SQLI for HTTP
							result = true;
							error.setText("");
							sqliController sqli = new sqliController(urlParameter.getText());
							String param = sqli.scan();
							
							if(sqli.v){
								SQLIV.setText("FOUND");
								SQLIParameter.setText(param);
								String u = urlParameter.getText();
								String usage = u.replace("$Vparam", param);
								SQLIUsage.setText(usage);
							}
							else{
								SQLIV.setText("NOT FOUND");
								SQLIParameter.setText("N/A");
								SQLIUsage.setText("N/A");
							}
						}
						else if(connectionController.isHTTPS(urlParameter.getText())){//Check if given URL is HTTPS type.
							//SQLI for HTTPS
							result = true;
							error.setText("");
							sqliController sqli = new sqliController(urlParameter.getText());
							String param = sqli.scanS();
							
							if(sqli.v){
								SQLIV.setText("FOUND");
								SQLIParameter.setText(param);
								String u = urlParameter.getText();
								String usage = u.replace("$Vparam", param);
								SQLIUsage.setText(usage);
							}
							else{
								SQLIV.setText("NOT FOUND");
								SQLIParameter.setText("N/A");
								SQLIUsage.setText("N/A");
							}
						}
						else{
							error.setText("URL is not HTTP/HTTPS");
							result = false;
						}
					}
					else{
						error.setText("URL does not contain $Vparam !");
						result = false;
					}
				}
				else{
					error.setText("URL is not valid !");
					result = false;
				}
			}
			
			if(XSSOption.isSelected()){ //Check if SQLI is selected.
				if(connectionController.isValidURL(urlParameter.getText()) && !urlParameter.getText().equals("")){//Check if given URL is valid.
					if(connectionController.isVparam(urlParameter.getText())){//Check if given URL contains $Vparam.
						if(connectionController.isHTTP(urlParameter.getText())){//Check if given URL is HTTP type.
							//XSS for HTTP
							result = true;
							error.setText("");
							xssController xss = new xssController(urlParameter.getText());
							String param = xss.scan();							
							if(xss.v){
								XSSV.setText("FOUND");
								XSSParameter.setText(param);
								String u = urlParameter.getText();
								String usage = u.replace("$Vparam", param);
								XSSUsage.setText(usage);
							}else{
								XSSV.setText("NOT FOUND");
								XSSParameter.setText("N/A");
								XSSUsage.setText("N/A");
							}
						}else if(connectionController.isHTTPS(urlParameter.getText())){//Check if given URL is HTTPS type.
							//XSS for HTTPS
							result = true;
							error.setText("");
							xssController xss = new xssController(urlParameter.getText());
							String param = xss.scanS();							
							if(xss.v){
								XSSV.setText("FOUND");
								XSSParameter.setText(param);
								String u = urlParameter.getText();
								String usage = u.replace("$Vparam", param);
								XSSUsage.setText(usage);
							}else{
								XSSV.setText("NOT FOUND");
								XSSParameter.setText("N/A");
								XSSUsage.setText("N/A");
							}
						}
						else{
							error.setText("URL is not HTTP/HTTPS");
							result = false;
						}
					}
					else{
						error.setText("URL does not contain $Vparam !");
						result = false;
					}
				}
				else{
					error.setText("URL is not valid !");
					result = false;
				}
			}
					
		} 
		catch (Exception e1) {
			// TODO Auto-generated catch block
		}finally{
			if(result){
				error.setText("");
				SingleSelectionModel<Tab> selectionModel = TRtab.getSelectionModel();
				selectionModel.select(0); //select by index starting with 0
				selectionModel.getSelectedItem().setDisable(true);
				selectionModel.select(1); //select by index starting with 0
				selectionModel.getSelectedItem().setDisable(false);
				menuItemSaveResult.setDisable(false);
			}
			
		}
		
		
	}

	public void menuItemNewScanClicked(){
		SingleSelectionModel<Tab> selectionModel = TRtab.getSelectionModel(); //select by index starting with 0
		selectionModel.select(1); 
		selectionModel.getSelectedItem().setDisable(true);
		selectionModel.select(0); 
		selectionModel.getSelectedItem().setDisable(false);
		urlParameter.setText("");
		cipherSuiteLabel.setVisible(false);
		cipherSuite.setVisible(false);	
		rInitURL.setText("");
		rServer.setText("");
		rStatus.setText("");
		rContentType.setText("");
		rLength.setText("");
		rExpiration.setText("");
		cipherSuite.setText("");
		SQLIV.setText("");
		SQLIUsage.setText("");
		SQLIParameter.setText("");
		XSSV.setText("");
		XSSParameter.setText("");
		XSSUsage.setText("");
		informationOption.setSelected(true);
		SQLIOption.setSelected(false);
		XSSOption.setSelected(false);
		menuItemSaveResult.setDisable(true);
		
	}
	
	public void menuItemExitClicked(){
		Stage stage = (Stage) informationOption.getScene().getWindow(); //informationOption is selected randomly to get actual window
		Boolean answer = confirmBox.display("Confirm", "Are you sure you want to exit?");
		if(answer){
			stage.close();
		}
	}
	
	public void menuItemSaveResultClicked(){
		try{
			Stage stage = (Stage) informationOption.getScene().getWindow();
			saveResultController save = new saveResultController(stage);
			String file = save.getFileName();
			
			if(save.isFile() && (file.contains(".txt")||file.contains(".TXT"))){
				save.setWriter();
				save.writeString("This document is created by Vulnarity.");
				save.writeString("###################START###################");
				save.writeString("Initial URL :\t\t"+ urlParameter.getText());
				save.writeString("Server : \t\t"+ rServer.getText());
				save.writeString("Status : \t\t"+ rStatus.getText());
				save.writeString("Content type :\t\t"+ rContentType.getText());
				save.writeString("Length : \t\t"+ rLength.getText());
				save.writeString("Expiration : \t\t"+ rExpiration.getText());
				save.writeString("Cipher Suite : \t\t"+ cipherSuite.getText());
				save.writeString("SQLI : \t\t\t"+ SQLIV.getText());
				save.writeString("SQLI Usage : \t\t"+ SQLIUsage.getText());
				save.writeString("SQLI Parameter : \t"+ SQLIParameter.getText());
				save.writeString("XSS : \t\t\t"+ XSSV.getText());
				save.writeString("XSS Usage : \t\t"+ XSSUsage.getText());
				save.writeString("XSS Parameter : \t"+ XSSParameter.getText());
				save.writeString("#####################END#################");
				save.closeWriter();
			}
			else if(save.isFile() && (file.contains(".xml")||file.contains(".XML"))){
				save.prepareToXML();
				
				informationModel infomodel = new informationModel();
				infomodel.setCipherSuite(cipherSuite.getText());
				infomodel.setContentType(rContentType.getText());
				infomodel.setExpiration(rExpiration.getText());
				infomodel.setInitialURL(urlParameter.getText());
				infomodel.setLength(rLength.getText());
				infomodel.setServer(rServer.getText());
				infomodel.setStatus(rStatus.getText());
				
				sqliModel sqlimodel = new sqliModel();
				sqlimodel.setSqliParameter(SQLIParameter.getText());
				sqlimodel.setSqliUsage(SQLIUsage.getText());
				sqlimodel.setSqliVulnerability(SQLIV.getText());
				
				xssModel xssmodel = new xssModel();
				xssmodel.setXssParameter(XSSParameter.getText());
				xssmodel.setXssUsage(XSSUsage.getText());
				xssmodel.setXssVulnerability(XSSV.getText());
				
				save.setInformation(infomodel);
				save.setSqli(sqlimodel);
				save.setXSS(xssmodel);
				
				save.writeToXML();
				
			}
			else{
				alertBox.display("Warning", "Operation is cancelled by user!");							
			}
		}catch(Exception e){}
		
	}

	public void menuItemOpenResultClicked(){
		try{
			Stage stage = (Stage) informationOption.getScene().getWindow();
			loadResultController load = new loadResultController(stage);
			String file = load.getFileName();
			
			if(load.isFile() && (file.contains(".xml")||file.contains(".XML"))){
				load.prepareFromXML();
				
				List<sqliModel> sqlimodel ;
				List<xssModel> xssmodel ;
				List<informationModel> informationmodel ;
				
				informationmodel = load.getInformation();
				sqlimodel = load.getSqli();
				xssmodel = load.getXss();
				
				SingleSelectionModel<Tab> selectionModel = TRtab.getSelectionModel(); 
				selectionModel.select(0); 
				selectionModel.getSelectedItem().setDisable(true);
				selectionModel.select(1); 
				selectionModel.getSelectedItem().setDisable(false);

				menuItemSaveResult.setDisable(false);
				cipherSuiteLabel.setVisible(true);
				cipherSuite.setVisible(true);	
				informationOption.setSelected(true);
				SQLIOption.setSelected(true);
				XSSOption.setSelected(true);
				
				urlParameter.setText(informationmodel.get(0).getInitialURL());
				rInitURL.setText(informationmodel.get(0).getInitialURL());
				rServer.setText(informationmodel.get(0).getServer());
				rStatus.setText(informationmodel.get(0).getStatus());
				rContentType.setText(informationmodel.get(0).getContentType());
				rLength.setText(informationmodel.get(0).getLength());
				rExpiration.setText(informationmodel.get(0).getExpiration());
				cipherSuite.setText(informationmodel.get(0).getCipherSuite());
				SQLIV.setText(sqlimodel.get(0).getSqliVulnerability());
				SQLIUsage.setText(sqlimodel.get(0).getSqliUsage());
				SQLIParameter.setText(sqlimodel.get(0).getSqliParameter());
				XSSV.setText(xssmodel.get(0).getXssVulnerability());
				XSSParameter.setText(xssmodel.get(0).getXssParameter());
				XSSUsage.setText(xssmodel.get(0).getXssUsage());
			}			
			else{
				alertBox.display("Warning", "Operation is cancelled by user!");							
			}
		}catch(Exception e){}
		
	}
		
	public void menuItemDocumentClicked(){
		Stage stage = (Stage) informationOption.getScene().getWindow(); //informationOption is selected randomly to get actual window
		Boolean answer = confirmBox.display("Confirm", "Are you sure you want to exit?");
		if(answer){
			stage.close();
		}
	}
	
	public void menuItemAboutClicked(){
		alertBox.display("About", "This application is developed by Berk Arslan for BsC project in KhPI.");		
	}

        public void calculateButtonClicked(){
            String av = AV.getValue().toString();
            String ac = AC.getValue().toString();
            String pr = PR.getValue().toString();
            String ui = UI.getValue().toString();
            String ci = CI.getValue().toString();
            String ii = II.getValue().toString();
            String ai = AI.getValue().toString();
            String s = S.getValue().toString();
            String cr = CR.getValue().toString();
            String ir = IR.getValue().toString();
            String ar = AR.getValue().toString();
            boolean scope = false;
            if(s.equals("Changed")){
                scope = true;
            }else if(s.equals("Not Changed")){
                scope = false;
            }
            
            cvssController cvss = new cvssController(scope);
            cvss.init(av, ac, pr, ui, ci, ii, ai, cr, ir, ar);
            double score = cvss.getBaseScore();
            double mScore = cvss.getMBaseScore();
            baseScore.setText(Double.toString(score));
            modifiedScore.setText(Double.toString(mScore));
        }
        
        @Override
        public void initialize(URL location, ResourceBundle resources) {
            // throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
             AV.getItems().addAll("Network","Adjacent Network","Local","Physical");
             AC.getItems().addAll("Low","High");
             PR.getItems().addAll("None","Low","High");
             UI.getItems().addAll("Not Required","Required");
             CI.getItems().addAll("None","Low","High");
             II.getItems().addAll("None","Low","High");
             AI.getItems().addAll("None","Low","High");
             S.getItems().addAll("Not Changed","Changed");
             CR.getItems().addAll("None","Low","Medium","High");
             IR.getItems().addAll("None","Low","Medium","High");
             AR.getItems().addAll("None","Low","Medium","High");

             AV.setOnMouseClicked(e->{
             metricDescription.setText("ATTACK VECTOR:\n\nThis metric reflects the context by which vulnerability exploitation is possible. This metric value will be larger the more remote an attacker can be in order to exploit the vulnerable component. The assumption is that the number of potential attackers for a vulnerability that could be exploited froma cross the Internet is larger than the number of potential attackers that could exploit a vulnerability requiring physical access to a device, and therefore warrants a greater score.");
             });
             AC.setOnMouseClicked(e->{
             metricDescription.setText("ATTACK COMPLEXITY:\n\nThis metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. As described below, such conditions may require the collection of more information about the target, the presence of certain system configuration settings, or computational exceptions. Importantly, the assessment of this metric excludes any requirements for user interaction in order to exploit the vulnerability (such conditions are captured in the User Interaction metric). This metric value is largest for the least complex attacks.");
             });
             PR.setOnMouseClicked(e->{
             metricDescription.setText("PRIVILEGE REQUIRED:\n\nThis metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. This metric is greatest if no privileges are required.");
             });
             S.setOnMouseClicked(e->{
             metricDescription.setText("SCOPE:\n\nFormally, Scope refers to the collection of privileges defined by a computing authority (e.g. an application, an operating system, or a sandbox environment) when granting access to computing resources (e.g. files, CPU, memory, etc). These privileges are assigned based on some method of identification and authorization. In some cases, the authorization may be simple or loosely controlled based upon predefined rules or standards. For example, in the case of Ethernet traffic sent to a network switch, the switch accepts traffic that arrives on its ports and is an authority that controls the traffic flow to other switch ports. The Base score is greater when a scope change has occurred.");
             });
             CI.setOnMouseClicked(e->{
             metricDescription.setText("CONFIDENTIALITY IMPACT:\n\nThis metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones. This metric value increases with the degree of loss to the impacted component.");
             });
             II.setOnMouseClicked(e->{
             metricDescription.setText("INTEGRITY IMPACT:\n\nThis metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. This metric value increases with the consequence to the impacted component.");
             });
             AI.setOnMouseClicked(e->{
             metricDescription.setText("AVAILABILITY IMPACT:\n\nThis metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the impacted component, this metric refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component. This metric value increases with the consequence to the impacted component.");
             });
             UI.setOnMouseClicked(e->{
             metricDescription.setText("USER INTERACTION:\n\nThis metric captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. This metric value is greatest when no user interaction is required.");
             });
             CR.setOnMouseClicked(e->{
             metricDescription.setText("SECURITY REQUIREMENTS:\n\nThese metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user's organization, measured in terms of Confidentiality, Integrity, and Availability. That is, if an IT asset supports a business function for which Availability is most important, the analyst can assign a greater value to Availability relative to Confidentiality and Integrity. Each security requirement has three possible values: Low, Medium, or High.\n" +
"\n" +
"The full effect on the environmental score is determined by the corresponding Modified Base Impact metrics. That is, these metrics modify the environmental score by reweighting the Modified Confidentiality, Integrity, and Availability impact metrics. For example, the Modified Confidentiality impact (MC) metric has increased weight if the Confidentiality Requirement (CR) is High. Likewise, the Modified Confidentiality impact metric has decreased weight if the Confidentiality Requirement is Low. The Modified Confidentiality impact metric weighting is neutral if the Confidentiality Requirement is Medium. This same process is applied to the Integrity and Availability requirements.\n" +
"\n" +
"Note that the Confidentiality Requirement will not affect the Environmental score if the (Modified Base) confidentiality impact is set to None. Also, increasing the Confidentiality Requirement from Medium to High will not change the Environmental score when the (Modified Base) impact metrics are set to High. This is because the modified impact sub score (part of the Modified Base score that calculates impact) is already at a maximum value of 10.For brevity, the same table is used for all three metrics. The greater the Security Requirement, the higher the score (recall that Medium is considered the default).");
             });
             IR.setOnMouseClicked(e->{
             metricDescription.setText("SECURITY REQUIREMENTS:\n\nThese metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user's organization, measured in terms of Confidentiality, Integrity, and Availability. That is, if an IT asset supports a business function for which Availability is most important, the analyst can assign a greater value to Availability relative to Confidentiality and Integrity. Each security requirement has three possible values: Low, Medium, or High.\n" +
"\n" +
"The full effect on the environmental score is determined by the corresponding Modified Base Impact metrics. That is, these metrics modify the environmental score by reweighting the Modified Confidentiality, Integrity, and Availability impact metrics. For example, the Modified Confidentiality impact (MC) metric has increased weight if the Confidentiality Requirement (CR) is High. Likewise, the Modified Confidentiality impact metric has decreased weight if the Confidentiality Requirement is Low. The Modified Confidentiality impact metric weighting is neutral if the Confidentiality Requirement is Medium. This same process is applied to the Integrity and Availability requirements.\n" +
"\n" +
"Note that the Confidentiality Requirement will not affect the Environmental score if the (Modified Base) confidentiality impact is set to None. Also, increasing the Confidentiality Requirement from Medium to High will not change the Environmental score when the (Modified Base) impact metrics are set to High. This is because the modified impact sub score (part of the Modified Base score that calculates impact) is already at a maximum value of 10.For brevity, the same table is used for all three metrics. The greater the Security Requirement, the higher the score (recall that Medium is considered the default).");
             });
             AR.setOnMouseClicked(e->{
             metricDescription.setText("SECURITY REQUIREMENTS:\n\nThese metrics enable the analyst to customize the CVSS score depending on the importance of the affected IT asset to a user's organization, measured in terms of Confidentiality, Integrity, and Availability. That is, if an IT asset supports a business function for which Availability is most important, the analyst can assign a greater value to Availability relative to Confidentiality and Integrity. Each security requirement has three possible values: Low, Medium, or High.\n" +
"\n" +
"The full effect on the environmental score is determined by the corresponding Modified Base Impact metrics. That is, these metrics modify the environmental score by reweighting the Modified Confidentiality, Integrity, and Availability impact metrics. For example, the Modified Confidentiality impact (MC) metric has increased weight if the Confidentiality Requirement (CR) is High. Likewise, the Modified Confidentiality impact metric has decreased weight if the Confidentiality Requirement is Low. The Modified Confidentiality impact metric weighting is neutral if the Confidentiality Requirement is Medium. This same process is applied to the Integrity and Availability requirements.\n" +
"\n" +
"Note that the Confidentiality Requirement will not affect the Environmental score if the (Modified Base) confidentiality impact is set to None. Also, increasing the Confidentiality Requirement from Medium to High will not change the Environmental score when the (Modified Base) impact metrics are set to High. This is because the modified impact sub score (part of the Modified Base score that calculates impact) is already at a maximum value of 10.For brevity, the same table is used for all three metrics. The greater the Security Requirement, the higher the score (recall that Medium is considered the default).");
             });
             
             
        }
}
