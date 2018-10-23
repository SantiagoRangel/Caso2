import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.*;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V1CertificateGenerator;
public class Cliente {

	public static final String HOST = "157.253.217.14";
	public static final int PUERTO = 8081;
	private PrivateKey llavePrivada;
	public PublicKey llavePublica;
	private Key llaveSimetrica;
	private String hmac;

	public Cliente(BufferedReader br)
	{

	}

	//Creacion de llaves publica y privada
	public void crearLlaves(int tamanioLlave) throws NoSuchAlgorithmException, NoSuchProviderException
	{ 
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

		generator.initialize(tamanioLlave);

		KeyPair pair = generator.generateKeyPair();
		llavePublica = pair.getPublic();
		llavePrivada = pair.getPrivate();
	}

	//Creación del Certificado Digital
	public X509Certificate crearCD(PublicKey llavePublicaServidor) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException
	{
		Random r = new Random();
		BigInteger serialNumber = new BigInteger(llavePublicaServidor.getEncoded().length, r);
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");

		String algoritmo = hmac;
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setSubjectDN(dnName);
		certGen.setPublicKey(llavePublicaServidor);
		certGen.setSignatureAlgorithm(algoritmo);
		return certGen.generate(llavePrivada, "BC");
	}


	//Cifrado Simétrico

	/*
	 * Metodo para encriptar dado un algoritmo, metodo de encriptacion, tamaño en bits y un texto
	 * Ej: AES, ECB, 128, bananana
	 */

	public String encriptarConPKSC5(String algoritmo, String metodo, String tamanio, String texto, PublicKey llaveServidor) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{

		byte[] enByt = texto.getBytes("UTF8");
		Cipher cipher = Cipher.getInstance(algoritmo + "/" + metodo + "/PKSC5Padding" );
		cipher.init(Cipher.ENCRYPT_MODE, llaveServidor);
		return new String(cipher.doFinal(enByt), "UTF8");
	}

	/*
	 * Metodo para desencriptar dado un algoritmo, un metodo de encriptacion, tamaño en bits y una llave
	 * Ej: AES, ECB, 128, bananana
	 */

	public String desencriptarConPKSC5(String algoritmo, String metodo, String tamanio, String texto, PublicKey llaveServidor) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		byte[] enByt = texto.getBytes("UTF8");

		KeyGenerator keyGen = KeyGenerator.getInstance(algoritmo);		
		keyGen.init(Integer.parseInt(tamanio));
		Cipher cipher = Cipher.getInstance(algoritmo + "/" + metodo + "/PKSC5Padding" );
		cipher.init(Cipher.DECRYPT_MODE, llaveServidor);
		// Decrypt the ciphertext using the same key
		byte[] newPlainText = cipher.doFinal(texto.getBytes("UTF8"));
		return new String(cipher.doFinal(enByt), "UTF8");
	}

	public static void main(String[] args) throws IOException
	{


		boolean ejecutar = true;
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;


		try
		{
			socket = new Socket(HOST, PUERTO); 
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			Cliente c = new Cliente(stdIn);
			String fromServer;
			String fromUser;
			System.out.print("Escriba el mensaje para enviar:");
			fromUser = stdIn.readLine();
			escritor.println(fromUser);
			int estado = 0;
			while (ejecutar && estado < 6 && fromUser  != null) 
			{
				switch(estado)
				{
				case 0:
					if (!(fromUser.equalsIgnoreCase("HOLA")))
					{
						ejecutar = false;
						escritor.println("ERROR");
					}
					else
					{
						escritor.println("HOLA");
						estado ++;
					}

				case 1:
					if ((fromServer = lector.readLine()).equals("OK"))
					{
						fromUser = "ALGORTIMOS:AES:RSA:HmacMD5";
						escritor.println(fromUser);
					}


				}	


			}

		} 
		catch (Exception e)
		{
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}

	}

}


