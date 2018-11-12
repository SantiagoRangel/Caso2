import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.swing.plaf.synth.SynthSeparatorUI;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class Cliente {

	public static final String HOST = "localhost";
	public static final int PUERTO = 8081;
	private static PrivateKey llavePrivada;
	public static PublicKey llavePublica;
	private static SecretKeySpec llaveSimetrica;
	private Date fecha;

	/*
	 * 400 carga 20 retardo 200 carga 40 retardo 80 carga 100 retardo
	 */
	public static int NUMERO_CARGA = 80;
	public static int RETRASO = 100;

	/*
	 * Para modificar el pool toca cambiarlo acá y en el servidor
	 */
	public static int NUMERO_THREADS = 1;

	/*
	 * SEGURO NOSEGURO
	 */
	public static String SEGURIDAD = "NOSEGURO";

	public Cliente() {

	}

	public Cliente(String seguridad) {
		SEGURIDAD = seguridad;
	}

	// Creacion de llaves publica y privada
	public static void crearLlaves() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");

		generator.initialize(1024);

		KeyPair pair = generator.generateKeyPair();
		llavePublica = pair.getPublic();
		llavePrivada = pair.getPrivate();
	}

	// Creación del Certificado Digital
	public static X509Certificate crearCD(KeyPair keypair)
			throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException,
			NoSuchProviderException, IOException, OperatorCreationException, CertificateException {
		SecureRandom random = new SecureRandom();

		X500Name subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Cliente").build();
		byte[] id = new byte[20];
		random.nextBytes(id);
		BigInteger serial = new BigInteger(160, random);
		Date startDate = Date.from(LocalDate.of(2000, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant()); // time from
		// which
		// certificate
		// is valid
		Date expiryDate = Date.from(LocalDate.of(2035, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant()); // time after
		// which
		// certificate
		// is not valid
		BigInteger serialNumber = serial; // serial number for certificate
		KeyPair keyPair = new KeyPair(llavePublica, llavePrivada); // EC public/private key pair
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName); // note: same as issuer
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256withRSA");
		return certGen.generate(keyPair.getPrivate(), "BC");
	}

	// Cifrado Simétrico

	/*
	 * Metodo para encriptar dado un algoritmo, metodo de encriptacion, tamaño en
	 * bits y un texto Ej: AES, ECB, 128, bananana
	 */

	// public static String encriptarConPKSC5(String algoritmo, String metodo,
	// byte[] texto, SecretKey llaveSecreta)throws NoSuchAlgorithmException,
	// NoSuchPaddingException, InvalidKeyException,
	// IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	// {
	// Cipher cipher = null;
	// byte[] enByt = texto;
	// if (algoritmo.equals("AES")) {
	// cipher = Cipher.getInstance(algoritmo);
	// } else {
	// cipher = Cipher.getInstance(algoritmo);
	// }
	// cipher.init(Cipher.ENCRYPT_MODE, llaveSecreta);
	// return new String(cipher.doFinal(enByt), "UTF8");
	// }
	//
	// /*
	// * Metodo para desencriptar dado un algoritmo, un metodo de encriptacion,
	// tamaño
	// * en bits y una llave Ej: AES, ECB, 128, bananana
	// */
	//
	// public static String desencriptarConPKSC5(String algoritmo, String metodo,
	// byte[] texto, PublicKey llavePub) throws IllegalBlockSizeException,
	// BadPaddingException,
	// UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException,
	// NoSuchPaddingException {
	// Cipher cipher = null;
	// if(algoritmo.equals("AES"))
	// cipher = Cipher.getInstance("RSA/ECB/PKCS5Padding");
	// else
	// {
	// cipher = Cipher.getInstance("RSA/CBC/PKCS5Padding");
	// }
	//
	// cipher.init(Cipher.DECRYPT_MODE, llavePub);
	// // Decrypt the ciphertext using the same key
	// byte[] newPlainText = cipher.doFinal(texto);
	// return new String(newPlainText, "UTF8");
	// }

	// Cifrado Asimetrico

	/*
	 * Metodo para desencriptar dado un algoritmo, un metodo de encriptacion, tamaño
	 * en bits y una llave Ej: AES, ECB, 128, bananana
	 */

	public static String procesoAsimetrico(byte[] texto, String algoritmo, PublicKey llavePub)
			throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException {

		try {
			Cipher cifrador = Cipher.getInstance("RSA");
			cifrador.init(Cipher.DECRYPT_MODE, llavePrivada);

			byte[] decoded = cifrador.doFinal(Hex.decode(texto));
			llaveSimetrica = new SecretKeySpec(decoded, 0, decoded.length, algoritmo);
			algoritmo += "/ECB/PKCS5Padding";
			String testo = new String(decoded, "UTF8");

			cifrador.init(Cipher.ENCRYPT_MODE, llavePub);
			byte[] cifrado = cifrador.doFinal(decoded);
			String textox = printByteArrayHexa(cifrado);
			return textox;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void procesoConCifrado() {
		boolean ejecutar = true;
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		try {
			socket = new Socket(HOST, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			Cliente c = new Cliente();
			String fromServer;
			String fromUser;
			System.out.print("Escriba el mensaje para enviar:");
			fromUser = "HOLA";
			escritor.println(fromUser);
			int estado = 0;
			String[] algoritmos;
			String algS;
			String algA;
			String hmac;
			X509Certificate certificadoS;
			while (ejecutar && fromUser != null) {

				fromServer = lector.readLine();
				System.out.println(fromServer);
				if (fromServer.equals("ERROR")) {
					System.out.println("ERROR");
					break;
				}
				System.out.print("Escriba los algoritmos");
				fromUser = "ALGORITMOS:AES:RSA:HMACMD5";
				escritor.println(fromUser);
				if (!fromUser.contains("ALGORITMOS")) {
					System.out.println("No contiene algoritmos");
					break;
				}
				algoritmos = fromUser.split(":");
				algS = algoritmos[1];
				algA = algoritmos[2];
				hmac = algoritmos[3];
				crearLlaves();
				boolean nuevo = true;
				while (ejecutar && nuevo) {
					fromServer = lector.readLine();
					if (fromServer.equals("ERROR")) {
						System.out.println("se murio");
						break;
					} else if (fromServer.equals("OK")) {
						System.out.println("todo piloto");
						X509Certificate certificadoC = crearCD(new KeyPair(llavePublica, llavePrivada));
						byte[] mybyte = certificadoC.getEncoded();
						String mycosa = DatatypeConverter.printHexBinary(mybyte);
						// Se envia el certificado
						escritor.flush();
						escritor.println(mycosa);
						escritor.flush();
						System.out.println(mycosa);
						// Se recibe el certificado del servidor
						CertificateFactory cf = CertificateFactory.getInstance("X509");
						System.out.println("Generando el certificado");
						String s = lector.readLine();
						System.out.println(s);
						if (!s.equals("OK")) {
							System.out.println("No se mandó bien el certificado");
							break;
						}
						System.out.println(s);
						s = lector.readLine();
						ByteArrayInputStream paraEsc = new ByteArrayInputStream(DatatypeConverter.parseHexBinary(s));

						System.out.println("maybe se traba");
						certificadoS = (X509Certificate) cf.generateCertificate(paraEsc);
						byte[] certificadoEnBytes = certificadoS.getEncoded();
						System.out.println("Termina de generarlo");
						escritor.println("OK");
						escritor.flush();
						// Se verifica la validez
						// try {
						// certificadoS.checkValidity();
						// System.out.println("El certificado es valido");
						// escritor.println("OK");
						// estado++;
						// } catch (Exception e) {
						// System.out.println("El certificado no es valido " + e.getCause() + " " +
						// e.getMessage());
						// escritor.println("ERROR");
						// break;
						// }
						fromServer = lector.readLine();
						// Se desencripta
						System.out.println("Entra a desencriptar, guardar y luego encriptar");
						String llavedescifrada = procesoAsimetrico(fromServer.getBytes(), algS,
								certificadoS.getPublicKey());
						escritor.println(llavedescifrada);
						// Recibe el mensaje y lo lee
						// Obtiene el hmac del Mensaje
						fromServer = lector.readLine();
						if (!fromServer.equals("OK")) {
							System.out.println("Falló");
							break;
						}
						System.out.println("Por favor ingrese la solicitud");
						fromUser = "1234";
						byte[] clearText = fromUser.getBytes();
						byte[] cifrao;
						byte[] macMesg;
						Mac mac = Mac.getInstance(hmac);
						mac.init(llaveSimetrica);
						macMesg = mac.doFinal(fromUser.getBytes());
						// Encripta y envía el mensaje
						Cipher cipher = Cipher.getInstance(algS);
						cipher.init(Cipher.ENCRYPT_MODE, certificadoS.getPublicKey());
						cifrao = cipher.doFinal(clearText);

						fromServer = printByteArrayHexa(cifrao);
						System.out.println(fromUser);
						escritor.println(fromUser);

						// Envía el hash del mensaje
						fromServer = printByteArrayHexa(macMesg);
						escritor.println(fromUser);
						nuevo = false;
						fromServer = lector.readLine();
						throw new Exception("Finaliza la comunicación");
					}
				}
			}

		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
	}

	public static void procesoSinCifrado() {

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		try {
			socket = new Socket(HOST, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			Cliente c = new Cliente();
			String fromServer;
			String fromUser;

			int estado = 0;

			long startVer = 0;

			// fromServer = lector.readLine();
			if (estado == 0) {
				System.out.print("Escriba el mensaje para enviar:");

				escritor.println(NUMERO_CARGA);
				fromUser = "HOLA";
				escritor.println(fromUser);

				estado++;
			} else if (estado == 1) {
				fromServer = lector.readLine();
				if (fromServer.equalsIgnoreCase("OK")) {
					System.out.println("OK");

					System.out.print("Escriba algoritmos para enviar:");

					fromUser = "ALGORITMOS:AES:RSA:HMACMD5";

					escritor.println(fromUser);
					estado++;
				} else {
					System.out.println(fromServer);
				}
			} else if (estado == 2) {
				// Se manda el certificado
				fromServer = lector.readLine();
				System.out.println(fromServer);
				if (fromServer.equalsIgnoreCase("OK")) {
					String certificadoEnString = "Certificado super seguro";
					System.out.println("Mandar certificado cliente");

					escritor.println(certificadoEnString);
					estado++;

				} else {
					System.out.println(fromServer);
				}

			} else if (estado == 3) {
				// Recibe el certificado

				fromServer = lector.readLine();
				System.out.println(fromServer);

				if (fromServer.equalsIgnoreCase("OK")) {
					fromServer = lector.readLine();
					System.out.println(fromServer);
					System.out.println("Recibir certificado servidor");

					escritor.println("OK");
					// -------------------Se comienza la medida del monitor para el tiempo de
					// verificación ---------
					startVer = System.currentTimeMillis();
					estado++;
				}

			} else if (estado == 4) {
				// Devolver la llave
				System.out.println("Devolver la llave");
				fromServer = lector.readLine();
				escritor.println(fromServer);

				estado++;

			} else if (estado == 5) {
				fromServer = lector.readLine();
				System.out.println(fromServer);

				// -------------------Se finaliza la medida del monitor para el tiempo de
				// verificación ---------
				long fin1 = System.currentTimeMillis();
				long resta1 = fin1 - startVer;

				Monitor.addTiemposVerificacion(resta1);

				System.out.println("Haga la consulta");

				fromUser = "1234";

				escritor.println(fromUser);
				// -------------------Se comienza la medida del monitor para el tiempo de
				// verificación ---------
				long start = System.currentTimeMillis();

				escritor.println("1234");

				fromServer = lector.readLine();
				System.out.println(fromServer);

				// -------------------Termina la medida del monitor para el tiempo de
				// verificación ---------
				long fin = System.currentTimeMillis();

				long resta = fin - start;

				Monitor.addTiemposConsulta(resta);
			}

			escritor.close();
			lector.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws IOException {

		Monitor monitor1 = new Monitor("verificacion");
		Monitor monitor2 = new Monitor("consulta");

		
		Cliente cliente = new Cliente("SEGURO");
		
		// String respuesta = stdIn.readLine();
		// TODO Cambiar por el parametro despues de probar
		if (cliente.SEGURIDAD.equals("NOSEGURO")) {
			System.out.println("Protocolo no seguro");
			procesoSinCifrado();

		} else if (cliente.SEGURIDAD.equals("SEGURO")) {
			System.out.println("Protocolo seguro");
			procesoConCifrado();

		}

		// Cliente c = new Cliente("SEGURO");

		ArrayList<ArrayList<Long>> listasVer = new ArrayList<>();
		ArrayList<ArrayList<Long>> listasConsul = new ArrayList<>();

		for (int i = 0; i < 10; i++) {

			Generador gen = new Generador(Cliente.NUMERO_CARGA, Cliente.RETRASO);
			ArrayList<Long> listaVerTemp = Monitor.getTiemposVerificacion();
			ArrayList<Long> listaConsulTemp = Monitor.getTiemposConsulta();

			listasVer.add(listaVerTemp);
			listasConsul.add( listaConsulTemp);

			Monitor.reiniciarArrayListVer();
			Monitor.reiniciarArrayListConsu();
		}
		String path = System.getProperty("user.dir");

		/*
		 * SEGURO|NOSEGURO-carga-#threads
		 * 
		 */
		String pruebaActual = Cliente.SEGURIDAD + "-" + Cliente.NUMERO_CARGA + "-" + Cliente.NUMERO_THREADS;

		String nombreArchivoVer = "verificaciones-" + pruebaActual + ".csv";
		String nombreArchivoConsul = "consultas-" + pruebaActual + ".csv";

		PrintWriter writerVerificacion = null;
		PrintWriter writerConsul = null;
		try {
			writerVerificacion = new PrintWriter(
					path + File.separator + "data" + File.separator + nombreArchivoVer);
			writerConsul = new PrintWriter(
					path + File.separator + "data" + File.separator + nombreArchivoConsul);
		} catch (Exception e) {
			e.printStackTrace();
		}
		writerVerificacion.println("sep=,");
		writerConsul.println("sep=,");

		// Imprime la información
		for (ArrayList<Long> arrayList : listasVer) {

			ArrayList<Long> datos = arrayList;
			StringBuilder builderVer = new StringBuilder();

			for (int i = 0; i < datos.size(); i++) {
				if (i != datos.size() - 1) {
					builderVer.append(datos.get(i) + ",");
					System.out.println("Entra " + datos.get(i));
				} else {
					builderVer.append(datos.get(i));
				}
			}

			writerVerificacion.println(builderVer.toString());

		}
		for (ArrayList<Long> arrayList2 : listasConsul) {

			StringBuilder builder2 = new StringBuilder();
			ArrayList<Long> datos2 = arrayList2;

			for (int i = 0; i < datos2.size(); i++) {
				if (i != datos2.size() - 1) {
					builder2.append(datos2.get(i) + ",");
					System.out.println("Entra " + datos2.get(i));
				} else {
					builder2.append(datos2.get(i));
				}

			}
			writerConsul.println(builder2.toString());
		}

		System.out.println("acaba de verificar");

		writerVerificacion.close();
		writerConsul.close();

		System.out.println("Tiempo verificacion " + Monitor.getTiemposDeVerificacionPromedio());

	}

	public static String printByteArrayHexa(byte[] byteArray) {
		String out = "";
		for (int i = 0; i < byteArray.length; i++) {
			if ((byteArray[i] & 0xff) <= 0xf) {
				out += "0";
			}
			out += Integer.toHexString(byteArray[i] & 0xff).toUpperCase();
		}
		System.out.println(out);
		return out;
	}
}
