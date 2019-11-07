package owl.cs.netvul.btp;

import java.io.File;
import java.net.URL;
import org.semanticweb.HermiT.ReasonerFactory;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.reasoner.InferenceType;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;

class PreScanReason {
	
	OWLOntologyManager man;
	URL nv,nvp;
	File f,fp;
	OWLOntology o,op;
	IRI ir;
	ReasonerFactory rf;
	OWLReasoner r;
	OWLDataFactory df;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		PreScanReason ps = new PreScanReason();
		ps.process();
	}
	
	public PreScanReason() {
		man = OWLManager.createOWLOntologyManager();
		nv=this.getClass().getClassLoader().getResource("nval.owl");
		nvp=this.getClass().getClassLoader().getResource("nvalPreProc.owl");
		f = new File(nv.getFile());
		fp=new File(nvp.getFile());
		df=man.getOWLDataFactory();
		
	}
	
	public void process() {
		try {
			o = man.loadOntologyFromOntologyDocument(f);
			op = man.loadOntologyFromOntologyDocument(fp);
			ir=o.getOntologyID().getOntologyIRI().get();
			OWLReasonerFactory rf=new ReasonerFactory();
			OWLReasoner ht = rf.createReasoner(op);
			ht.precomputeInferences(InferenceType.CLASS_ASSERTIONS,InferenceType.OBJECT_PROPERTY_ASSERTIONS);
			InferredOntologyGenerator iog = new InferredOntologyGenerator(ht);
			iog.fillOntology(df, o);
			man.saveOntology(o);
		}catch(OWLOntologyCreationException e) {
			e.printStackTrace();
			man.clearOntologies();
			System.exit(1);
		} catch (OWLOntologyStorageException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			man.clearOntologies();
			System.exit(1);
		}
		man.clearOntologies();
	}

}
