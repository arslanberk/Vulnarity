package org.arslan.vulnarity.controller;

import javafx.application.Application;
import static javafx.application.Application.launch;
import javafx.stage.Stage;
import org.arslan.vulnarity.view.mainView;


public class MainApp extends Application {

    @Override
    public void start(Stage stage) throws Exception {
        mainiew window =new  mainView("Vulnarity", 800, 600);
	window.display();
    }

    /**
     * The main() method is ignored in correctly deployed JavaFX application.
     * main() serves only as fallback in case the application can not be
     * launched through deployment artifacts, e.g., in IDEs with limited FX
     * support. NetBeans ignores main().
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        launch(args);
    }

}
