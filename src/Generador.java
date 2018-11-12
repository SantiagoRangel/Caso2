import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generador 
{
	private LoadGenerator gen;

	public Generador(int numberTasks, int gapBetween)
	{
		Task work = createTask();	
		gen = new LoadGenerator("Cliente-Server" , numberTasks, work, gapBetween); 
		gen.generate();
	}

	public void comenzar() 
	{
		gen.generate();
	}

	public Task createTask() 
	{
		return new ClienteTask();
	}
}
