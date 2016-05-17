package org.arslan.vulnarity.controller;

import java.util.List;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.SingleSelectionModel;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleButton;
import javafx.stage.Stage;
import org.arslan.vulnarity.model.informationModel;
import org.arslan.vulnarity.model.sqliModel;
import org.arslan.vulnarity.model.xssModel;
import org.arslan.vulnarity.view.confirmBox;
import org.arslan.vulnarity.view.alertBox;

public class mainController {
	
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
}
