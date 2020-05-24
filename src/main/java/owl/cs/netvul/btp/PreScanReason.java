package owl.cs.netvul.btp;

import java.io.File;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.semanticweb.HermiT.Configuration;
import org.semanticweb.HermiT.Configuration.TableauMonitorType;
import org.semanticweb.HermiT.ReasonerFactory;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.reasoner.ConsoleProgressMonitor;
import org.semanticweb.owlapi.reasoner.InferenceType;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.util.AutoIRIMapper;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;

class PreScanReason {
	
	OWLOntologyManager man;
	URL nv,nvp;
	File f,fp;
	OWLOntology o,op;
	IRI ir;
	ReasonerFactory rf;
	OWLReasoner r;
	AutoIRIMapper aim;
	OWLDataFactory df;
	volatile Integer i;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		PreScanReason ps = new PreScanReason();
		ps.preprocess();
		ps.process();
	}
	
	public PreScanReason() {
		man = OWLManager.createOWLOntologyManager();
		aim = new AutoIRIMapper(new File("src/main/resources"),false);
		man.getIRIMappers().add(aim);
		nv=this.getClass().getClassLoader().getResource("nval.owl");
		nvp=this.getClass().getClassLoader().getResource("nvalPreProc.owl");
		f = new File(nv.getFile());
		fp=new File(nvp.getFile());
		df=man.getOWLDataFactory();
		
	}
	
	public void preprocess() {
		ExecutorService es = Executors.newCachedThreadPool();
		i=0;
		while(i<2) {
			//System.out.println(i);
			es.execute(new Runnable() {
				public void run() {
					try {
						File f1;
						synchronized(i){
							Integer k=++i;
							URL pp1 = this.getClass().getClassLoader().getResource("nvalPreProc"+k.toString()+".owl");
							//System.out.println(pp1.toString());
							f1 = new File(pp1.getFile());
						}
						o=man.loadOntologyFromOntologyDocument(f);
						op=man.loadOntologyFromOntologyDocument(f1);
						ir=o.getOntologyID().getOntologyIRI().get();
						Configuration config = new Configuration();
						// config.tableauMonitorType= TableauMonitorType.DEBUGGER_HISTORY_ON;
						//config.reasonerProgressMonitor=new ConsoleProgressMonitor();
						OWLReasonerFactory rf=new ReasonerFactory();
						OWLReasoner ht = rf.createReasoner(op,config);
						ht.precomputeInferences(InferenceType.CLASS_ASSERTIONS,InferenceType.OBJECT_PROPERTY_ASSERTIONS);
						InferredOntologyGenerator iog = new InferredOntologyGenerator(ht);
						synchronized(o) {
							iog.fillOntology(df, o);
						}
						synchronized(man) {
							man.saveOntology(o);
							ht.dispose();
						}
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
				}
			});
		}
		es.shutdown();
		try {
			es.awaitTermination(Long.MAX_VALUE, TimeUnit.HOURS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			man.clearOntologies();
			System.exit(1);
		}
		man.clearOntologies();
	}
	
	public void process() {
		try {
			o = man.loadOntologyFromOntologyDocument(f);
			op = man.loadOntologyFromOntologyDocument(fp);
			ir=o.getOntologyID().getOntologyIRI().get();
			Configuration config = new Configuration();
			// config.tableauMonitorType= TableauMonitorType.DEBUGGER_HISTORY_ON;
			config.reasonerProgressMonitor=new ConsoleProgressMonitor();
			OWLReasonerFactory rf=new ReasonerFactory();
			OWLReasoner ht = rf.createReasoner(op,config);
			ht.precomputeInferences(InferenceType.CLASS_ASSERTIONS,InferenceType.OBJECT_PROPERTY_ASSERTIONS);
			InferredOntologyGenerator iog = new InferredOntologyGenerator(ht);
			iog.fillOntology(df, o);
			man.saveOntology(o);
			ht.dispose();
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
