import java.lang.management.ManagementFactory;
import java.util.ArrayList;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class Monitor extends Thread
{
	private static ArrayList<Long> tiemposVerificacion = new ArrayList<>();
	private static ArrayList<Long> tiemposConsulta = new ArrayList<>();
	
	private long inicVer; 
	private long startConsu;
	private double memoria;	
	private boolean terminado;
	private String caso;
	
	public Monitor(String pCaso)
	{
		this.caso = pCaso;
		terminado = false; 
	}
	
	@Override
	public void run()
	{
		long start = System.currentTimeMillis();
		try 
		{
			synchronized (this) 
			{				
				wait();
				System.out.println("paso: " + caso);
			}			
		} 
		catch (InterruptedException e) 
		{
			e.printStackTrace();
		} 
		long tiempo = System.currentTimeMillis()-start;
		System.out.println("se demoro "+ tiempo + " milisegundos en " + caso );		
		if(caso.equals("verificacion"))
		{
			addVer(tiempo);
		}
		else if(caso.equals("consulta")) 
		{
			addConsulta(tiempo);
		}		
		terminado = true; 
	}		

	public double getSystemCpuLoad() throws Exception 
	{				
		 MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		 ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
		 AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
		 if (list.isEmpty()) return Double.NaN;
		 Attribute att = (Attribute)list.get(0);
		 Double value = (Double)att.getValue();
		 // usually takes a couple of seconds before we get real values
		 if (value == -1.0) return Double.NaN;
		 // returns a percentage value with 1 decimal point precision
		 return ((int)(value * 1000) / 10.0);
	}
	
	public long endVer()
	{			 
		long tiempo = System.currentTimeMillis()-inicVer;		
		System.out.println("Se demoro: "+ tiempo + " milisegundos en Verificar");
		synchronized (this) 
		{					
			tiemposVerificacion.add(tiempo);			
		}		
		return tiempo; 
	}
	
	public long endConsu()
	{			
		long tiempo = System.currentTimeMillis()-inicVer; 		
		System.out.println("Se demoro: "+ tiempo + " milisegundos en Consultar");
		synchronized (this) 
		{
				tiemposConsulta.add(tiempo);
		}		
		return tiempo; 
	}
	
	public static double getTiemposDeConsultaPromedio()
	{
		double prom = 0; 		
		for (Long cons : tiemposConsulta) 
		{
			prom += (double)(cons/tiemposConsulta.size());
		}		
		return prom; 		
	}	
	
	public static double getTiemposDeVerificacionPromedio()
	{
		double prom = 0; 		
		for (Long ver : tiemposVerificacion) 
		{
			prom += (double)(ver/tiemposVerificacion.size());
		}	
		System.out.println("Promedio: " + prom + " milisegundos");		
		return prom ; 		
	}
	
	public void termino(String pCaso)
	{
		terminado = true; 
		caso= pCaso;		
	}
	
	public void comenzar()
	{
		inicVer = System.currentTimeMillis(); 
		System.out.println("Inicio: " + inicVer);
	}	
	
	public synchronized void addConsulta(long cons)
	{
		tiemposConsulta.add(cons);
	}	
	
	public synchronized void addVer(long ver)
	{
		tiemposVerificacion.add(ver);
	}
	
	public synchronized static void addTiemposVerificacion(long x)
	{
		tiemposVerificacion.add(x); 
	}
	
	public synchronized static void addTiemposConsulta(long x)
	{
		tiemposConsulta.add(x); 
	}	
	
	public static ArrayList<Long> getTiemposVerificacion()
	{
		return tiemposVerificacion; 
	}
	
	public static ArrayList<Long> getTiemposConsulta()
	{
		return tiemposConsulta; 
	}
	
	public static void reiniciarArrayListVer()
	{
		tiemposVerificacion = new ArrayList<Long>(); 
	}
	
	public static void reiniciarArrayListConsu()
	{
		tiemposConsulta = new ArrayList<Long>(); 
	}
	
	public boolean getTermino()
	{
		return terminado; 
	}
}
