package model;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptingFileSystem {
	
	
	//====================================================================================
								//Algoritmo generador hash
	//====================================================================================
	//Este metodo es una funcion criptografica hash que se encarga de generar un hash
	//de 160 bits (20 bytes) de cualquier valor de entrada
	//
	//Como parametros tenemos:
	//---> inputFile: Es el archivo que el algoritmo va a encriptar
	//---> outputFile: Es el archivo ya encriptado
	//====================================================================================
	public void generateSHA1(File inputFile, File outputFile) throws Exception {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

		byte[] dataBytes = new byte[1024];
		int readFile = 0;
		while ((readFile = fileInputStream.read(dataBytes)) != -1) {
			sha1.update(dataBytes, 0, readFile);
		}
		;
		byte[] hashBytes = sha1.digest();

		StringBuffer bufferString = new StringBuffer();
		for (int i = 0; i < hashBytes.length; i++) {
			bufferString.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1));
		}
		String fileHash = bufferString.toString();
		
		fileOutputStream.write(fileHash.getBytes(Charset.forName("UTF-8")));
		
		fileInputStream.close();
		fileOutputStream.close();

	}
	//============ FIN ==============
	
	
	

	//====================================================================================
									//Algoritmo calcula el  SHA1
	//====================================================================================
	//Este metodo es una funcion criptografica hash
	//
	//
	//Como parametros tenemos:
	//---> file: Es el archivo selecionado.
	//====================================================================================
	public String computeSHA1(File file) throws Exception {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		FileInputStream fis = new FileInputStream(file);

		byte[] data = new byte[1024];
		int read = 0;
		while ((read = fis.read(data)) != -1) {
			sha1.update(data, 0, read);
		}
		;
		byte[] hashBytes = sha1.digest();

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < hashBytes.length; i++) {
			sb.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1));
		}

		String fileHash = sb.toString();
		fis.close();
		return fileHash;
	}
	//============ FIN ==============
	
	
	
	
	//=================================================================================================
								//Algoritmo verificador SHA1
	//=================================================================================================
	//Este metodo se encarga de verificar si el SHA1 del archivo de entrada es el mismo que el hash.
	//
	//Este metodo retorna (verdadero) si el sha1 del archivo de entrada es el mimo que fue generado por
	//el metodo generateSHA1
	//
	//Como parametros tenemos:
	//---> inputFile: Es el archivo que el algoritmo va a encriptar
	//---> sha1: Es la clave qur se utiliza para el algoritmo AES
	//=================================================================================================
	public boolean verifySHA1(File inputFile, File sha1) throws Exception {
		String inputHashFile = null;
		BufferedReader bufferedReader = new BufferedReader(new FileReader(sha1));
		while ((inputHashFile = bufferedReader.readLine()) != null) {
			inputHashFile = inputHashFile.trim();
			break;
		}
		bufferedReader.close();
		
		String sha1InputFile = computeSHA1(inputFile);
		
		return sha1InputFile.equals(inputHashFile);
		
	}
	//============ FIN ==============
	
	
	

	//====================================================================================
							//Algoritmo de encriptacion de archivos.
	//====================================================================================
	//Este metodo se encarga de cifrar cualquier archivo utilizando una clave de 128 bits
	//generada por el algoritmo de PBKDF2.
	//
	//Como parametros tenemos:
	//---> generatedKey: Es la clave qur se utiliza para el algoritmo AES
	//---> inputFile: Es el archivo que el algoritmo va a encriptar
	//---> outputFile: Es el archivo ya encriptado
	//====================================================================================
	public void encryptFile(byte[] generatedKey, File inputFile, File outputFile) throws Exception {
		/*
		 * The cipher is initialized from the AES algorithm
		 */
		KeySpec keySpec = new SecretKeySpec(generatedKey, "AES");
		Cipher cipherAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipherAES.init(Cipher.ENCRYPT_MODE, (SecretKeySpec) keySpec);

		/*
		 * The input/output streams are initialized to read the files
		 */
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

		/*
		 * The size of the buffer is set, in this case 64 bytes
		 */
		int bufferBytesSize = Math.min(fileInputStream.available(), 64);
		byte[] buffer = new byte[bufferBytesSize];
		
		/*
		 * If bytes still fit in the buffer, keep reading the input file
		 */
		while (buffer.length == 64) {
			fileInputStream.read(buffer);
			byte[] bufferEncrypted = cipherAES.update(buffer);
			fileOutputStream.write(bufferEncrypted);
			bufferBytesSize = Math.min(fileInputStream.available(), 64);
			buffer = new byte[bufferBytesSize];
		}
		fileInputStream.read(buffer);
		byte[] encryptedBuffer = cipherAES.doFinal(buffer);
		fileOutputStream.write(encryptedBuffer);

		fileInputStream.close();
		fileOutputStream.close();

	}
	//============ FIN ==============
	
	
	
	//==============================================================================================
								//Algoritmo de desencriptado de archivos.
	//==============================================================================================
	//Este metodo se encarga de descifrar cualquier archivo utilizando un generador de 128 bits
	//
	//Como parametros tenemos:
	//---> keyAES: Es la clave que se utiliza para el algoritmo AES
	//---> inputFile: Es la ruta o ubicacion del archivo que se va a desencriptar
	//---> outputFile: Es la ruta en la cual se almacena el archivo de salida desencriptado
	//==============================================================================================
	public void decryptFile(byte[] keyAES, File inputFile, File outputFile) throws Exception {
	
		
		KeySpec keySpec = new SecretKeySpec(keyAES, "AES");
		Cipher cipherAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipherAES.init(Cipher.DECRYPT_MODE, (SecretKeySpec) keySpec);		
		
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
		
		int bufferBytesSize = Math.min(fileInputStream.available(), 64);
		byte[] buffer = new byte[bufferBytesSize];
		while (buffer.length == 64) {
			fileInputStream.read(buffer);
			byte[] bufferEncrypted = cipherAES.update(buffer);
			fileOutputStream.write(bufferEncrypted);
			bufferBytesSize = Math.min(fileInputStream.available(), 64);
			buffer = new byte[bufferBytesSize];
		}
		fileInputStream.read(buffer);
		byte[] encryptedBuffer = cipherAES.doFinal(buffer);
		fileOutputStream.write(encryptedBuffer);
		
		fileInputStream.close();
		fileOutputStream.close();
		
	}
	//============ FIN ==============

	
	
	
	//==============================================================================================
								//Algoritmo de funcion de derivacion de clave
	//==============================================================================================
	//Implementacion del PBKDF2, funcion de derivacion de clave con un costo computacional variable,
	//que se utiliza para reducir las vulnerabilidades de los ataques de fuerza bruta.
	//
	//Tambien esta funcion, es parte de la serie de estandares criptagraficos de clave publica (PKCS) 
	//de RSA Laboratories.
	//
	//Este metodo retorna la clave de la funcion en un Array de bits.
	//
	//Como parametros tenemos:
	//---> password: Es la contraseña ingresada por el usuario, de la cual se optiene una clave derivada.
	//---> salt: Esta se compone de de bits aletorios que se utilizan como una de las entradas en una
	//funcion de derivacion de clave
	//---> numberIterations: Es el numero de iteraciones para la funcion PBKDF
	//---> keyLength: Es la longitud de la clave generada en bits
	//==============================================================================================
	public byte[] PBKDF2(char[] password, byte[] salt, int numberIterations, int keyLength) {
		try {
			SecretKeyFactory secretKF = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec PBEKeySpec = new PBEKeySpec(password, salt, numberIterations, keyLength);
			SecretKey secretKey = secretKF.generateSecret(PBEKeySpec);
			return secretKey.getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
	//============ FIN ==============

}
