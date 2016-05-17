package org.arslan.vulnarity.controller;

import org.arslan.vulnarity.view.alertBox;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.arslan.vulnarity.model.informationModel;
import org.arslan.vulnarity.model.resultModel;
import org.arslan.vulnarity.model.sqliModel;
import org.arslan.vulnarity.model.xssModel;

public class saveResultController {
	private FileChooser fileChooser;
	private Stage stage;
	private File file;
	private PrintWriter writer;
	private JAXBContext context;
	private Marshaller marshaller;
	private resultModel resultXML;
	
	/**
	 * Constructor for save result controller.
	 * @param stage
	 */
	public saveResultController(Stage stage){
		this.stage=stage;
		fileChooser = new FileChooser();
		fileChooser.setTitle("Save Result");
		fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("XML", "*.xml"),
                new FileChooser.ExtensionFilter("TXT", "*.txt")
                );
	}
	
	/**
	 * Opens fileChooser and gets target file name.
	 * @return String: file path
	 */
	public String getFileName(){  
		try {
            	file = fileChooser.showSaveDialog(stage);	
            } catch (Exception ex) {
                alertBox.display("Error", "File does not exist!");
            }
        return file.getPath().toString();
	}
	
	/**
	 * Prepares writer object for future use.
	 */
	public void setWriter(){
		try {
			writer = new PrintWriter(file.getPath().toString(), "UTF-8");
		} catch (FileNotFoundException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			 alertBox.display("Error", "File does not exist!");
		}
	}
	
	/**
	 * Writes String to a line of target file.
	 * @param line
	 */
	public void writeString(String line){
		writer.println(line);
	}
	
	/**
	 * Closes writer.
	 */
	public void closeWriter(){
   		writer.close();
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
	 * Creates JAXBContext, Marshaller and resultModel Object
	 */
	public void prepareToXML(){
		try {
			context = JAXBContext.newInstance(resultModel.class);
			marshaller = context.createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			resultXML = new resultModel();
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}       
	}
	
	/**
	 * Gets informationModel into List<informationModel>, and pass it to resultModel.
	 * @param info
	 */
	public void setInformation(informationModel info){
		List<informationModel> i = new ArrayList<informationModel>();
		i.add(info);
		resultXML.setInformation(i);
	}
	
	/**
	 * Gets sqliModel into List<sqliModel>, and pass it to resultModel.
	 * @param info
	 */
	public void setSqli(sqliModel info){
		List<sqliModel> i = new ArrayList<sqliModel>();
		i.add(info);
		resultXML.setSqli(i);
	}
	
	/**
	 * Gets sqliModel into List<sqliModel>, and pass it to resultModel.
	 * @param info
	 */
	public void setXSS(xssModel info){
		List<xssModel> i = new ArrayList<xssModel>();
		i.add(info);
		resultXML.setXss(i);
	}
	
	/**
	 * Writes to XML file.
	 */
	public void writeToXML(){
		try {
			marshaller.marshal(resultXML, file);
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
