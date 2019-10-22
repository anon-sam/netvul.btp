package owl.cs.netvul.btp;

import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;

class ParseData {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		ParseData pd=new ParseData();
		pd.parseCAPEC();
		pd.parseCWE();
	}
	
	public void parseCWE() {
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
		try {
			SAXParser saxParser = saxParserFactory.newSAXParser();
			CWEHandler cwhand = new CWEHandler();
			ClassLoader cl = ClassLoader.getSystemClassLoader();
			String cw = cl.getResource("1000.xml").toString();
			saxParser.parse(cw, cwhand);
		}catch (ParserConfigurationException e) {
	        e.printStackTrace();
	    } catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void parseCAPEC() {
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
		try {
			SAXParser saxParser = saxParserFactory.newSAXParser();
			CAPECHandler cphand = new CAPECHandler();
			ClassLoader cl = ClassLoader.getSystemClassLoader();
			String cw = cl.getResource("3000.xml").toString();
			saxParser.parse(cw, cphand);
		}catch (ParserConfigurationException e) {
	        e.printStackTrace();
	    } catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
