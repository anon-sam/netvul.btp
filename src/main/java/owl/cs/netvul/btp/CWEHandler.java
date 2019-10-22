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
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

class CWEHandler extends DefaultHandler{
	
	OWLOntologyManager man;
	OWLOntology o;
	OWLDataFactory df;
	OWLNamedIndividual n;
	IRI ir;
	
	boolean isRelAtk = false;
	boolean isRelWeakness = false;
	
	public CWEHandler() {	
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
	}

	
	
	@Override
	public void startElement(String uri,String localName,String qName,Attributes attributes) throws SAXException{
		if(qName.equalsIgnoreCase("Weakness")) {
			String name = attributes.getValue("Name");
			String id = attributes.getValue("id");
			OWLObjectProperty op = df.getOWLObjectProperty(ir+"#hasCWE");
			OWLNamedIndividual i = df.getOWLNamedIndividual(ir+"#CWE_ID="+id);
			n = df.getOWLNamedIndividual(ir+"#WK_"+name);
			if(!o.containsIndividualInSignature(n.getIRI())) {
				OWLClass atk = df.getOWLClass(ir+"#Weakness");
				OWLClassAssertionAxiom at = df.getOWLClassAssertionAxiom(atk, n);
				OWLAnnotation ur = df.getOWLAnnotation(df.getRDFSSeeAlso(), df.getOWLLiteral("https://cwe.mitre.org/data/definitions/+"+id+".html"));
				OWLAnnotationAssertionAxiom uratk = df.getOWLAnnotationAssertionAxiom(n.getIRI(), ur);
				man.addAxiom(o, at);
				man.addAxiom(o, uratk);
			}
			if(!o.containsIndividualInSignature(i.getIRI())) {
				OWLClass cap = df.getOWLClass(ir+"#CWE");
				OWLClassAssertionAxiom at = df.getOWLClassAssertionAxiom(cap, i);
				man.addAxiom(o, at);
			}
			OWLObjectPropertyAssertionAxiom atca = df.getOWLObjectPropertyAssertionAxiom(op, n, i);
			man.addAxiom(o, atca);
		}
		else if(qName.equalsIgnoreCase("Related_Attack_patterns")) {
			isRelAtk=true;
		}
		else if(qName.equalsIgnoreCase("Related_Attack_pattern") && isRelAtk) {
			String aid = "CAPEC_ID="+attributes.getValue("CAPEC_ID");
			OWLNamedIndividual rw = df.getOWLNamedIndividual(ir+"#CAPEC_ID="+aid);
			if(!o.containsIndividualInSignature(rw.getIRI())) {
				OWLClass cap = df.getOWLClass(ir+"#CAPEC");
				OWLClassAssertionAxiom at = df.getOWLClassAssertionAxiom(cap, rw);
				man.addAxiom(o, at);
			}
			OWLObjectProperty ex = df.getOWLObjectProperty(ir+"#exploitedBy");
			OWLObjectPropertyAssertionAxiom relwk = df.getOWLObjectPropertyAssertionAxiom(ex, n, rw);
			man.addAxiom(o, relwk);
		}
		else if(qName.equalsIgnoreCase("Related_weaknesses")) {
			isRelWeakness = true;
		}
		else if(qName.equalsIgnoreCase("related_weakness")&&isRelWeakness) {
			String aid = attributes.getValue("CWE_ID");
			String nature = attributes.getValue("Nature");
			OWLNamedIndividual rw = df.getOWLNamedIndividual(ir+"#CWE_ID="+aid);
			if(!o.containsIndividualInSignature(rw.getIRI())) {
				OWLClass cap = df.getOWLClass(ir+"#CWE");
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
		else if(qName.equalsIgnoreCase("related_weaknesses")&&isRelWeakness) {
			isRelWeakness = false;
		}
		else if(qName.equalsIgnoreCase("weakness")) {
			try {
				man.saveOntology(o);
			} catch (OWLOntologyStorageException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else if(qName.equalsIgnoreCase("weaknesses")) {
			man.clearOntologies();
		}
	}
	
	@Override
	public void characters(char ch[],int start,int length) throws SAXException{
		
	}

}
