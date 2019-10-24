package owl.cs.netvul.btp;

import java.io.File;
import java.io.IOException;
import java.net.URL;

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
	OWLNamedIndividual n;
	OWLClass vul;
	OWLClass cw;
	OWLObjectProperty caus;
	IRI ir;

	/*public static void main(String[] args) {
		// TODO Auto-generated method stub
		CVEParser cv=new CVEParser();
		cv.parse();
	}*/
	
	public CVEParser() {
		ClassLoader cl = ClassLoader.getSystemClassLoader();
		URL nv = cl.getResource("nval.owl");
		//System.out.println(nv);
		File f = new File(nv.getFile());
		//ir=IRI.create(f);
		man =  OWLManager.createOWLOntologyManager();
		df= man.getOWLDataFactory();
		try {
			o = man.loadOntologyFromOntologyDocument(f);
			ir=o.getOntologyID().getOntologyIRI().get();
		} catch (OWLOntologyCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		vul = df.getOWLClass(ir+"#Vulnerability");
		caus = df.getOWLObjectProperty(ir+"#causedBy");
		cw = df.getOWLClass(ir+"#CWE");
	}
	
	public void parse() {
		ClassLoader cl = ClassLoader.getSystemClassLoader();
		for(int i=2002;i<=2019;i++) {
			String cw = cl.getResource("nvd/nvdcve-1.1-"+i+".json").getFile();
			JsonFactory factory = new JsonFactory();
			JsonParser parser;
			try {
				File f= new File(cw);
				parser  = factory.createParser(f);
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
							man.addAxiom(o, vcv);
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
							man.addAxiom(o, cs);
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
									man.addAxiom(o, uratk);
								}
							
							}while(jsin==null || !"description".equals(jsin));
							
						}
					}
					if(sv) {
						try {
							man.saveOntology(o);
						} catch (OWLOntologyStorageException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			} catch (JsonParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		man.clearOntologies();
	}
}
