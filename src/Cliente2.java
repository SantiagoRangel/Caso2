import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente2 {
	
	public static final String HOST = "157.253.217.14";
	public static final int PUERTO = 8081;
	private BufferedReader br;
	
	public Cliente2(BufferedReader br)
	{
		this.br = br;
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
		Cliente2 c = new Cliente2(stdIn);
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
