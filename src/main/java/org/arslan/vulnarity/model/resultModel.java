package org.arslan.vulnarity.model;

import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Results")
public class resultModel {
	
	private List<informationModel> information;
	private List<sqliModel> sqli;
	private List<xssModel> xss;

	@XmlElement(name = "information")
    public List<informationModel> getInformation() {
        return information;
    }
    
    @XmlElement(name = "sqli")
    public List<sqliModel> getSqli() {
        return sqli;
    }
    
    @XmlElement(name = "xss")
    public List<xssModel> getXss() {
        return xss;
    }
    
    public void setInformation(List<informationModel> information) {
        this.information = information;
    }
    
    public void setSqli(List<sqliModel> sqli) {
        this.sqli = sqli;
    }
    
    public void setXss(List<xssModel> xss) {
        this.xss = xss;
    }
}
