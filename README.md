# Encrypting File System

Proyecto final del curso de ciberseguridad de la Universidad ICESI, en el cual se implementa un encriptador/desencriptador de archivos. El programa tiene la siguiente funcionalidad:

1. Para encriptar, el programa recibe como entrada un archivo y una contraseña ingresadas por el usuario. A partir de la contraseña, se genera una clave de 128 bits, donde se emplea el algoritmo PBKDF2. El archivo se encripta con el algoritmo AES, usando la clave ingresada; el resultado se escribe a otro archivo, que contiene también el hash SHA-256 del archivo sin encriptar.

2. Para desencriptar, el programa recibe como entrada un archivo encriptado, el hash y la contraseña. El programa desencripta el archivo y escribe el resultado en un nuevo archivo. Despues, computa el hash SHA-1 del archivo desencriptado y lo compara con el hash almacenado con el archivo encriptado.


### Tecnologías usadas
- Java 17.2
- JavaFX 17.2
- Eclipse IDE


### ¿Cómo correr el proyecto?
Los siguientes pasos son para compilar y hacer funionar el proyecto con javaFX:

1. Verificar que al momento de usar el Eclipse IDE tener la extensión e(fx)clipse instalada desde el Eclipse Marketplace.

2. Si no posee el SDK de javaFX en su computador, descargarlo desde la siguiente página oficial: "https://gluonhq.com/products/javafx/" NOTA: se recomienda
descargar la versión que coincida con la versión de java que tiene instalada en su computadora. Es decir, si tiene java 17.XX, descargar la versión de 
javaFX 17.XX.

3. Una vez descargado el SDK de javaFX para su correspondiente sistema operativo, extraer la carpeta y guardarla en el lugar de su preferencia.

4. Ir a la pestaña Window en Eclipse y seleccionar la opción Preferences. Una vez allí, buscar la opción que dice Java -> Build Path -> User Libraries y, en la parte derecha, seleccionar la opción New...

5. A continuación se abrira un cuadro de dialogo donde escibiremos el nombre que le queremos dar a la nueva User Library. Una vez escrito el nombre, le damos en OK.

6. Teniendo seleccionada la libreria que acabamos de crear, le damos en la opción Add Externals JARS en el panel de la parte derecha. Allí, se nos abrira
el buscador de archivos y tendremos que irnos a la carpeta lib que se encuentra dentro de la carpeta que extraimos cuando descargamos el SDK de javaFX.

7. Una vez dentro de la carpeta lib, seleccionamos todos los archivos .jar que se encuentran allí y le damos en aceptar.

8. Devuelta en nuestro Eclipse IDE, y con la libreria creada con sus JARS, le damos en el botón Apply and Close.

9. Seleccionando nuestro proyecto en el Package Explorer (Viene ubicado por defecto en la parte izquierda de nuestro Eclipse IDE), 
dar click en Build Path -> Configure Build Path. Una vez se abra el cuadro de conficuración, irnos a la pestaña Libraries y seleccionando ModulePath, le damos en la opción Add Library del panel de la izquierda.

10. Cuando se abra la nueva ventana, seleccionar User Library y dar click en Next. A continuación, seleccionamos la libreria que creamos y le damos en Finish y luego Apply and Close. De esta manera, ya el proyecto debería reconocernos la libreria de javaFX.

### Autores:
- Bryan Alexander Guapacha Florez --> [Perfil de github](https://github.com/BryanGF0822)
- Paola Andrea Osorio Holguín --> [Perfil de github](https://github.com/paoos9513)

