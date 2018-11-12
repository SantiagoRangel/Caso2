import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generador {

	private LoadGenerator generador;

	public Generador(int numberTasks, int gapBetween)
	{
		Task work = createTask();
	
		generador = new LoadGenerator("Cliente-Server" , numberTasks, work, gapBetween); 
		generador.generate();
	}

	public void comenzar() {

		generador.generate();
	}

	public Task createTask() {

		return new ClienteTask();
	}

}
