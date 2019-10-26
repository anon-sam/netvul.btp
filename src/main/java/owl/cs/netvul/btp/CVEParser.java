package owl.cs.netvul.btp;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAnnotation;
import org.semanticweb.owlapi.model.OWLAnnotationAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

public class CVEParser {
	
	OWLOntologyManager man;
	OWLOntology o;
	OWLDataFactory df;
	//OWLNamedIndividual n;
	OWLClass vul;
	//OWLClass cw;
	OWLObjectProperty caus;
	//ClassLoader cl;
	List<Integer> A;
	int k;
	IRI ir;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		CVEParser cv=new CVEParser();
		cv.parse();
	}
	
	public CVEParser() {
		//ClassLoader cl = ClassLoader.getSystemClassLoader();
		URL nv = CVEParser.class.getClassLoader().getResource("nval.owl");
		//System.out.println(nv);
		File f = new File(nv.getFile());
		//ir=IRI.create(f);
		k=0;
		A=new ArrayList<>();
		for(int i=2002;i<=2019;i++)
			A.add(i);
		//A=List.of(2002,2003,2004,2005,2006,2007,2008,2009,2010,2011,2012,2013,2014,2015,2016,2017,2018,2019);
		man =  OWLManager.createOWLOntologyManager();
		df= man.getOWLDataFactory();
		try {
			o = man.loadOntologyFromOntologyDocument(f);
			ir=o.getOntologyID().getOntologyIRI().get();
		} catch (OWLOntologyCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			man.clearOntologies();
			System.exit(1);
		}
		vul = df.getOWLClass(ir+"#Vulnerability");
		caus = df.getOWLObjectProperty(ir+"#causedBy");
		//cw = df.getOWLClass(ir+"#CWE");
	}
	
	public void parse() {
		
		ExecutorService es = Executors.newFixedThreadPool(18);
		for(int i=0;i<18;i++) {
			es.execute(new Runnable() {
				public void run() {
					OWLNamedIndividual n=null;
					ClassLoader cl = ClassLoader.getSystemClassLoader();
					String cwfn;
					synchronized(A) {
						cwfn = cl.getResource("nvd/nvdcve-1.1-"+A.get(k).toString()+".json").getFile();
						k++;
					}
					JsonFactory factory = new JsonFactory();
					JsonParser parser;
					try {
						File f= new File(cwfn);
						parser  = factory.createParser(f);
						//ExecutorService asynwrit = Executors.newCachedThreadPool();
						while(!parser.isClosed()) {
							JsonToken jst = parser.nextToken();
							boolean sv = false;
							if(JsonToken.FIELD_NAME.equals(jst)) {
								String fname = parser.getCurrentName();
								if(fname.equals("cve")) {
									sv=true;
									String jsin=null;
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
									}while(jsin ==null || !"ID".equals(jsin));
									jst= parser.nextToken();
									String vname = parser.getValueAsString();
									n = df.getOWLNamedIndividual(ir+"#"+vname);
									OWLClassAssertionAxiom vcv = df.getOWLClassAssertionAxiom(vul, n);
									synchronized(man){
										man.addAxiom(o, vcv);
									}
									//System.out.println(parser.getValueAsString());
									//return;
								}
								else if(fname.equals("problemtype")) {
									String jsin=null;
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
									}while(jsin==null || !"value".equals(jsin));
									jst= parser.nextToken();
									OWLNamedIndividual wk = df.getOWLNamedIndividual(ir+"#"+parser.getValueAsString());
									OWLObjectPropertyAssertionAxiom cs = df.getOWLObjectPropertyAssertionAxiom(caus, n, wk);
									synchronized(man) {
										man.addAxiom(o, cs);
									}
								}
								else if(fname.equals("references")) {
									String jsin=null;
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
										if(jsin!=null && "url".equals(jsin)) {
											jst= parser.nextToken();
											OWLAnnotation ur = df.getOWLAnnotation(df.getRDFSSeeAlso(), df.getOWLLiteral(parser.getValueAsString()));
											OWLAnnotationAssertionAxiom uratk = df.getOWLAnnotationAssertionAxiom(n.getIRI(), ur);
											synchronized(man) {
												man.addAxiom(o, uratk);
											}
										}
							
									}while(jsin==null || !"description".equals(jsin));
							
								}
							}
							if(sv) {
								try {
									synchronized(man) {
										man.saveOntology(o);
									}
								} catch (OWLOntologyStorageException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
									man.clearOntologies();
									System.exit(1);
								}
							}
						}
					} catch (JsonParseException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						man.clearOntologies();
						System.exit(1);
					} catch (IOException e) {
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
}
