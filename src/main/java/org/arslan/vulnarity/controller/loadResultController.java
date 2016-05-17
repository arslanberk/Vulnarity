package org.arslan.vulnarity.controller;

import org.arslan.vulnarity.view.alertBox;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.arslan.vulnarity.model.informationModel;
import org.arslan.vulnarity.model.resultModel;
import org.arslan.vulnarity.model.sqliModel;
import org.arslan.vulnarity.model.xssModel;

public class loadResultController {
	
	private FileChooser fileChooser;
	private Stage stage;
	private File file;
	private JAXBContext context;
	private Unmarshaller unmarshaller;
	private resultModel resultXML;
	
	/**
	 * Constructor for load result controller.
	 * @param stage
	 */
	public loadResultController(Stage stage){
		this.stage=stage;
		fileChooser = new FileChooser();
		fileChooser.setTitle("Open Result");
		fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("XML", "*.xml")
                );
	}
	
	/**
	 * Opens fileChooser and gets target file name.
	 * @return String: file path
	 */
	public String getFileName(){  
		try {
            	file = fileChooser.showOpenDialog(stage);	
            } catch (Exception ex) {
                alertBox.display("Error", "File does not exist!");
            }
        return file.getPath().toString();
	}
	
	/**
	 * Checks if file is selected.
	 * @return boolean: true if file exists, or false.
	 */
	public boolean isFile(){
		if(file!=null)
		{
			return true;
		}else{
			return false;
		}
	}
	
	/**
	 * Creates JAXBContext, Unmarshaller and resultModel Object
	 */
	public void prepareFromXML(){
		try {
			context = JAXBContext.newInstance(resultModel.class);
			unmarshaller = context.createUnmarshaller();
			resultXML = (resultModel)unmarshaller.unmarshal(file);
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}       
	}
	
	/**
	 *  @param info
	 *  @return List<informationModel>
	 */
	public List<informationModel> getInformation(){
		List<informationModel> i = new ArrayList<informationModel>();
		i.addAll(resultXML.getInformation());
		return i;
	}
	
	/**
	 * @param info
	 * @return List<sqliModel>
	 */
	public List<sqliModel> getSqli(){
		List<sqliModel> i = new ArrayList<sqliModel>();
		i.addAll(resultXML.getSqli());
		return i;
	}
	
	/**
	 * @param info
	 * @return List<xssModel>
	 */
	public List<xssModel> getXss(){
		List<xssModel> i = new ArrayList<xssModel>();
		i.addAll(resultXML.getXss());
		return i;
	}
	
	
	

}
