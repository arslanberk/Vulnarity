package org.arslan.vulnarity.view;

import javafx.stage.*;
import javafx.scene.*;
import javafx.scene.layout.*;
import javafx.scene.control.*;
import javafx.geometry.*;

public class alertBox {


    public static void display(String title, String message) {
        Stage window = new Stage();
        window.initModality(Modality.APPLICATION_MODAL);
        window.setTitle(title);
        window.setMinWidth(250);
        Label label = new Label();
        label.setText(message);


        HBox first = new HBox(10);
        first.getChildren().add(label);
        first.setAlignment(Pos.CENTER);
       
        HBox space1 = new HBox(10);
        HBox space2 = new HBox(10);
        
        VBox layout = new VBox(10);
        //Add buttons
        layout.getChildren().addAll( space1, first, space2);
        
        layout.setAlignment(Pos.CENTER);
        Scene scene = new Scene(layout);
        window.setScene(scene);
        window.showAndWait();

    }

}