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
		int ok = 0;

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
		while (ejecutar && fromUser  != null) 
		{
			
			fromServer = lector.readLine();
			System.out.println(fromServer);
			if (fromServer.equals("ERROR"))
			{
				System.out.println("se murio");
				break;
			}
			System.out.print("Escriba los algoritmos");
			fromUser = stdIn.readLine();
			escritor.println(fromUser);
			fromServer = lector.readLine();
			if (fromServer.equals("ERROR"))
			{
				System.out.println("se murio");
				break;
			}
			else if(fromServer.equals("OK"))
			{
				System.out.println("todo piloto");
			}
			fromServer = lector.readLine();
			System.out.print(fromServer);
			fromServer = lector.readLine();
			System.out.print(fromServer);
			System.out.println("Mandar Certificado");
			fromUser = stdIn.readLine();
			escritor.println(fromUser);
			
				if (fromServer.equals("ERROR"))
				{
					System.out.println("se murio");
					break;
				}
				else if(fromServer.equals("OK"))
				{
					System.out.println("todo piloto");
					break;
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
