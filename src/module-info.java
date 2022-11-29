module fileEncripter {
	requires javafx.controls;
	requires javafx.fxml;
	requires javafx.graphics;
	
	opens userInterface to javafx.graphics, javafx.fxml;
	opens controller  to javafx.fxml;
}
