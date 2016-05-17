package org.arslan.vulnarity.view;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class mainView {

	private Parent root;
	private Stage stage;
	
	public mainView(String title, int width, int height) throws Exception{
		root = FXMLLoader.load(getClass().getResource("/fxml/main.fxml"));
		stage = new Stage();
                root.getStylesheets().add("/styles/Styles.css");
		stage.setOnCloseRequest(e ->{
			e.consume();
			Boolean answer = confirmBox.display("Confirm", "Are you sure you want to exit?");
			if(answer){
				stage.close();
			}
		});
		stage.setTitle(title);
		stage.setScene(new Scene(root,width,height));
		
	
	}
	
	public void display(){
		try{
			stage.show();	
		}
		catch(Exception e){}
	}

	
}
