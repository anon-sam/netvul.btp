package owl.cs.netvul.btp;

import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.OWLOntologyManager;

/**
 * Hello world!
 *
 */
public class App 
{
	//Create OWLOntologyManager
	public static void main(String[] args) {
	  OWLOntologyManager man = OWLManager.createOWLOntologyManager();
	  System.out.println(man.getOntologies().size());
	}

}
