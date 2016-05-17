package org.arslan.vulnarity.view;

import javafx.stage.*;
import javafx.scene.*;
import javafx.scene.layout.*;
import javafx.scene.control.*;
import javafx.geometry.*;

public class confirmBox {

    //Create variable
    static boolean answer;

    public static boolean display(String title, String message) {
        Stage window = new Stage();
        window.initModality(Modality.APPLICATION_MODAL);
        window.setTitle(title);
        window.setMinWidth(250);
        Label label = new Label();
        label.setText(message);

        //Create two buttons
        Button yesButton = new Button("Yes");
        Button noButton = new Button("No");

        //Clicking will set answer and close window
        yesButton.setOnAction(e -> {
            answer = true;
            window.close();
        });
        noButton.setOnAction(e -> {
            answer = false;
            window.close();
        });

        HBox first = new HBox(10);
        first.getChildren().add(label);
        first.setAlignment(Pos.CENTER);
        HBox second = new HBox(10);
        second.setAlignment(Pos.CENTER);
        second.getChildren().addAll(yesButton, noButton);
        HBox space1 = new HBox(10);
        HBox space2 = new HBox(10);
        
        VBox layout = new VBox(10);
        //Add buttons
        layout.getChildren().addAll( space1, first, second, space2);
        
        layout.setAlignment(Pos.CENTER);
        Scene scene = new Scene(layout);
        window.setScene(scene);
        window.showAndWait();

        //Make sure to return answer
        return answer;
    }

}