package controller;

import java.io.File;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import model.EncryptingFileSystem;

public class MenuInterfaceController {

	public final static String SALT = "1234";
	public final static int ITERATIONS = 10000;
	public final static int KEY_LENGTH = 128;

	private EncryptingFileSystem fileED;
	private File inputEncryptedFile;
	private File inputDecryptedFile;
	private File inputHashFile;
	
	
	
	
	//============================================================================================================
				// Referencias hacia los inputs del MenuInterface para el área de encriptar archivos.
	//============================================================================================================
	@FXML
	private TextField fileSelectedToEncript_inputText;
	@FXML
	private PasswordField passwordFileToEncript_inputText;
	//============ FIN ==============
	
	
	
	//============================================================================================================
				// Referencias hacia los inputs del MenuInterface para el área de desencriptar archivos
	//============================================================================================================
	@FXML
	private TextField fileSelectedToDecript_inputText;
	@FXML
	private TextField hashFile_inputText;
	@FXML
	private PasswordField passwordFileToDecript_inputText;
	//============ FIN ==============
	
	
	
	//=====================================================
			//Inicializacion de la aplicacion.
	//=====================================================
	@FXML
	void initialize() {
		this.fileED = new EncryptingFileSystem();
	}
	//============ FIN ==============
	
	
	
	//================================================================================
								// Limpieza de campos.
	//================================================================================
	private void clearFields() {
		this.passwordFileToDecript_inputText.setText("");
		this.passwordFileToEncript_inputText.setText("");
		this.fileSelectedToDecript_inputText.setText("");
		this.fileSelectedToEncript_inputText.setText("");
		this.hashFile_inputText.setText("");
		
		this.inputDecryptedFile = null;
		this.inputEncryptedFile = null;
		this.inputHashFile = null;
	}
	//============ FIN ==============
	
	
	
	//================================================================================
						//Metodos para la fase de encriptado de archivos.
	//================================================================================
	@FXML
	void encriptFileButton(ActionEvent event) {

		if (validateEmptyFields(this.passwordFileToEncript_inputText)) {
			
			//English translation: You should complete all the fields to encrypt a file
			showErrorAlert("Debe completar todos los campos para encriptar un archivo");

		} else {
			if (inputEncryptedFile != null) {
				char[] password = this.passwordFileToEncript_inputText.getText().toCharArray();

				try {
					byte[] key = fileED.PBKDF2(password, SALT.getBytes(), ITERATIONS, KEY_LENGTH);
					File outEnc = new File(inputEncryptedFile.getAbsolutePath() + ".cif");
					File outHash = new File(inputEncryptedFile.getAbsolutePath() + ".hash");
					this.fileED.encryptFile(key, this.inputEncryptedFile, outEnc);
					this.fileED.generateSHA1(this.inputEncryptedFile, outHash);
					
					//ENglish translation: The file has been ecrypted successfully
					showInfoAlert("El archivo ha sido encriptado con éxito");
					clearFields();
					
				} catch (Exception e1) {
					e1.printStackTrace();
				}

			} else {
				//English translation: You should choose a file to encrypt
				showErrorAlert("Debe elegir un archivo para encriptar.");
			}
		}

	}
	
	@FXML
	void fileToEncriptSelectButton(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		
		//English translation: Search a file to encrypt
		fileChooser.setTitle("Buscar un archivo para encriptar");

		fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("All Images", "*.*"));

		File file = fileChooser.showOpenDialog(null);

		if (file != null) {
			this.inputEncryptedFile = file;
			this.fileSelectedToEncript_inputText.setText(file.getPath());
		}
	}
	//============ FIN ==============
	
	
	
	//================================================================================
					//Metodos para la fase de desencriptado de archivos.
	//================================================================================
	@FXML
	void decriptFileButton(ActionEvent event) {

		if (validateEmptyFields(this.passwordFileToDecript_inputText)) {
			
			//English translation: You should complete all the fields to decrypt a file
			showErrorAlert("Debe completar todos los campos para descifrar un archivo");

		} else {
			if (this.inputDecryptedFile != null && this.inputHashFile != null) {

				char[] password = this.passwordFileToDecript_inputText.getText().toCharArray();

				try {
					String path = this.inputDecryptedFile.getAbsolutePath();
					path = path.substring(0, path.length() - 4);
					File outDec = new File(path);

					byte[] key = this.fileED.PBKDF2(password, SALT.getBytes(), ITERATIONS, KEY_LENGTH);

					this.fileED.decryptFile(key, this.inputDecryptedFile, outDec);

					if (this.fileED.verifySHA1(outDec, this.inputHashFile)) {
						//English translation: Your file has been decrypted becauses the hashes are the same
						showInfoAlert("Su archivo ha sido descifrado porque los hashes son los mismos");
						clearFields();

					} else {
						//English translation: The hashes are not the same, therefore your file could have been modified
						showInfoAlert("Los hashes no son los mismos, por lo que su archivo podría haber sido modificado");
						clearFields();
					}

				} catch (Exception e1) {
					e1.printStackTrace();
					//English translation: The password doesn't match
					showErrorAlert("La contraseña no coincide");
				}

			} else {
				//English translation: You should choose a file and its respective hash to decrypt it
				showErrorAlert("Debes elegir un archivo y su respectivo hash para desencriptarlo");
			}
		}
	}

	

	@FXML
	void fileHashSelectButton(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		
		//English translation: Search a file hash to encrypt
		fileChooser.setTitle("Busca el hash de un archivo para encriptarlo.");

		fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("All FILES", "*.*"),
				new FileChooser.ExtensionFilter("HASH", "*.hash"));

		File file = fileChooser.showOpenDialog(null);

		if (file != null) {
			this.inputHashFile = file;
			this.hashFile_inputText.setText(file.getPath());
		}
	}

	@FXML
	void fileToDecriptSelectButton(ActionEvent event) {
		FileChooser fileChooser = new FileChooser();
		
		//English translation: Search a file to decrypt
		fileChooser.setTitle("Buscar un archivo para desencriptar");

		fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("All FILES", "*.*"),
				new FileChooser.ExtensionFilter("CIF", "*.cif"));

		File file = fileChooser.showOpenDialog(null);

		if (file != null) {
			this.inputDecryptedFile = file;
			this.fileSelectedToDecript_inputText.setText(file.getPath());
		}
	}
	//============ FIN ==============
	
	

	//================================================================================
								// Alertas y errores.
	//================================================================================
	private void showErrorAlert(String message) {

		Alert alert = new Alert(Alert.AlertType.ERROR);
		alert.setHeaderText(null);
		alert.setTitle("Error");
		alert.setContentText(message);
		alert.showAndWait();
	}

	private void showInfoAlert(String message) {

		Alert alert = new Alert(Alert.AlertType.INFORMATION);
		alert.setHeaderText(null);
		alert.setTitle("Error");
		alert.setContentText(message);
		alert.showAndWait();
	}
	//============ FIN ==============
	
	
	
	//================================================================================
							// Validacion de campos vacios.
	//================================================================================
	private boolean validateEmptyFields(PasswordField field) {
		return field.getText() == null || field.getText().compareTo("") == 0;
	}
	//============ FIN ==============
	
}
