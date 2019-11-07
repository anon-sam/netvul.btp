package owl.cs.netvul.btp;

import java.io.File;
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
import org.semanticweb.owlapi.model.OWLSameIndividualAxiom;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

class CAPECHandler extends DefaultHandler{

	OWLOntologyManager man;
	OWLOntology o;
	OWLDataFactory df;
	OWLNamedIndividual n;
	OWLClass atk;
	OWLClass cap;
	//OWLObjectProperty op;
	IRI ir;
	
	boolean isRelAtk = false;
	
	public CAPECHandler() {
		//ClassLoader cl = ClassLoader.getSystemClassLoader();
		URL nv = CAPECHandler.class.getClassLoader().getResource("nval.owl");
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
			man.clearOntologies();
			System.exit(1);
		}
		atk = df.getOWLClass(ir+"#Attack");
		cap = df.getOWLClass(ir+"#CAPEC");
		//op = df.getOWLObjectProperty(ir+"#hasCAPEC");
	}
	
	@Override
	public void startElement(String uri,String localName,String qName,Attributes attributes) throws SAXException{
		if(qName.equalsIgnoreCase("Attack_Pattern")) {
			String name = attributes.getValue("Name");
			String id = attributes.getValue("ID");
			
			OWLNamedIndividual i = df.getOWLNamedIndividual(ir+"#CAPEC-"+id);
			n = df.getOWLNamedIndividual(ir+"#ATK_"+name);
			if(!o.containsIndividualInSignature(n.getIRI())) {
				
				OWLClassAssertionAxiom at = df.getOWLClassAssertionAxiom(atk, n);
				OWLAnnotation ur = df.getOWLAnnotation(df.getRDFSSeeAlso(), df.getOWLLiteral("https://capec.mitre.org/data/definitions/"+id+".html"));
				OWLAnnotationAssertionAxiom uratk = df.getOWLAnnotationAssertionAxiom(n.getIRI(), ur);
				man.addAxiom(o, at);
				man.addAxiom(o, uratk);
			}
			if(!o.containsIndividualInSignature(i.getIRI())) {
				
				OWLClassAssertionAxiom at = df.getOWLClassAssertionAxiom(cap, i);
				man.addAxiom(o, at);
			}
			//OWLObjectPropertyAssertionAxiom atca = df.getOWLObjectPropertyAssertionAxiom(op, n, i);
			OWLSameIndividualAxiom atca=df.getOWLSameIndividualAxiom(n,i);
			man.addAxiom(o, atca);
		}
		else if(qName.equalsIgnoreCase("Related_Attack_patterns")) {
			isRelAtk=true;
		}
		else if(qName.equalsIgnoreCase("Related_Attack_pattern") && isRelAtk) {
			String aid = attributes.getValue("CAPEC_ID");
			String nature = attributes.getValue("Nature");
			OWLNamedIndividual rw = df.getOWLNamedIndividual(ir+"#CAPEC-"+aid);
			if(!o.containsIndividualInSignature(rw.getIRI())) {
				
				OWLClassAssertionAxiom at = df.getOWLClassAssertionAxiom(cap, rw);
				man.addAxiom(o, at);
			}
			OWLObjectProperty nat = df.getOWLObjectProperty(ir+"#"+nature);
			OWLObjectPropertyAssertionAxiom relwk = df.getOWLObjectPropertyAssertionAxiom(nat, n, rw);
			man.addAxiom(o, relwk);
		}
	}
	
	@Override
	public void endElement(String uri,String localName,String qName)throws SAXException{
		if(qName.equalsIgnoreCase("Related_attack_patterns")&&isRelAtk) {
			isRelAtk=false;
		}
		else if(qName.equalsIgnoreCase("Attack_pattern")) {
			try {
				man.saveOntology(o);
			} catch (OWLOntologyStorageException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				man.clearOntologies();
				System.exit(1);
			}
		}
		else if(qName.equalsIgnoreCase("attack_patterns")) {
			man.clearOntologies();
		}
	}
	
	@Override
	public void characters(char ch[],int start,int length) throws SAXException{
		
	}


}
