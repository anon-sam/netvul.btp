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
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
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
	OWLDataProperty descp;
	//ClassLoader cl;
	volatile List<Integer> A;
	volatile int k;
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
		descp = df.getOWLDataProperty(ir+"#Description");
		//cw = df.getOWLClass(ir+"#CWE");
	}
	
	public void parse() {
		int processors = Runtime.getRuntime().availableProcessors();
		//System.out.println(processors);
		while(k!=A.size()) {
		ExecutorService es =Executors.newFixedThreadPool(processors);
		for(int i=0;i<processors;i++) {
			if(k==A.size()) {
				break;
			}
			es.execute(new Runnable() {
				public void run() {
					OWLNamedIndividual n=null;
					//OWLNamedIndividual wk=null;
					//OWLClassAssertionAxiom vcv=null;
					//OWLObjectPropertyAssertionAxiom cs=null;
					//OWLAnnotation ur=null;
					//OWLAnnotationAssertionAxiom uratk=null;
					//ClassLoader cl = ClassLoader.getSystemClassLoader();
					String wkname="";
					String annotname="";
					String desc="";
					String cwfn;
					synchronized(A) {
						cwfn = this.getClass().getClassLoader().getResource("nvd/nvdcve-1.1-"+A.get(k).toString()+".json").getFile();
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
									
									
									
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
									}while(jsin ==null || !"problemtype".equals(jsin));
									
									
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
									}while(jsin==null || !"value".equals(jsin));
									jst= parser.nextToken();
									if(!(parser.getValueAsString().startsWith("CWE-") || parser.getValueAsString().startsWith("NVD"))) {
										String jsoin=null;
										do {
											jst=parser.nextToken();
											if(JsonToken.FIELD_NAME.equals(jst)) {
												jsoin=parser.getCurrentName();
											}
										}while(jsoin==null || !"description".equals(jsoin));
										sv=false;
										continue;
									}
									wkname=parser.getValueAsString();
									
									
									
									
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
									}while(jsin==null || !"references".equals(jsin));
									
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
										if(jsin!=null && "url".equals(jsin)) {
											jst= parser.nextToken();
											annotname=parser.getValueAsString();
										
										}
							
									}while(jsin==null || !"description".equals(jsin));
									
									
									do {
										jst = parser.nextToken();
										if(JsonToken.FIELD_NAME.equals(jst)) {
											jsin = parser.getCurrentName();
										}
										if(jsin!=null && "value".equals(jsin)) {
											jst= parser.nextToken();
											desc=parser.getValueAsString();
											break;
										
										}
							
									}while(jsin==null || !"configurations".equals(jsin));
									
								}
								
							}
							if(sv) {
								try {
									OWLClassAssertionAxiom vcv = df.getOWLClassAssertionAxiom(vul, n);
									OWLNamedIndividual wk = df.getOWLNamedIndividual(ir+"#"+wkname);
									OWLObjectPropertyAssertionAxiom cs = df.getOWLObjectPropertyAssertionAxiom(caus, n, wk);
									OWLAnnotation ur = df.getOWLAnnotation(df.getRDFSSeeAlso(), df.getOWLLiteral(annotname));
									OWLAnnotationAssertionAxiom uratk = df.getOWLAnnotationAssertionAxiom(n.getIRI(), ur);
									OWLDataPropertyAssertionAxiom descax = df.getOWLDataPropertyAssertionAxiom(descp, n, desc);
									synchronized(man) {
										man.addAxiom(o, vcv);
										if(wkname.startsWith("CWE-")) {
											man.addAxiom(o, cs);
										}
										man.addAxiom(o, uratk);
										man.addAxiom(o, descax);
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
		}
		man.clearOntologies();
	}
}
