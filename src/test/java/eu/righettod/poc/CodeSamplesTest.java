package eu.righettod.poc;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXParseException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.File;

/**
 * Contains all samples of code used into the README.md file.
 */
public class CodeSamplesTest {

    /**
     * Sample for XML External Entity attack prevention
     *
     * @throws Exception Global error
     */
    @Test(expected = SAXParseException.class)
    public void testSampleXXE() throws Exception {
        /*Create a XML document builder factory*/
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        /*Disable External Entity resolution for differents cases*/
        // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all XML entity attacks are prevented
        // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
        String feature = "http://apache.org/xml/features/disallow-doctype-decl";
        dbf.setFeature(feature, true);

        // If you can't completely disable DTDs, then at least do the following:
        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
        // JDK7+ - http://xml.org/sax/features/external-general-entities
        feature = "http://xml.org/sax/features/external-general-entities";
        dbf.setFeature(feature, false);

        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
        // JDK7+ - http://xml.org/sax/features/external-parameter-entities
        feature = "http://xml.org/sax/features/external-parameter-entities";
        dbf.setFeature(feature, false);

        // feature external DTDs as well
        feature = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
        dbf.setFeature(feature, false);

        // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks" (see reference below)
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);

        /*Load XML file*/
        DocumentBuilder builder = dbf.newDocumentBuilder();
        //Here an org.xml.sax.SAXParseException will be throws because the sample XML contains a External Entity....
        builder.parse(new File("src/test/resources/SampleXXE.xml"));
    }

    /**
     * Sample for XPATH query injection prevention
     *
     * @throws Exception Global error
     */
    @Test
    public void testSampleXPath() throws Exception {
        /*Create a XML document builder factory*/
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        /*Disable External Entity resolution for differents cases*/
        //Do not performed here in order to focus on variable resolver code
        //but do it for production code !

        /*Load XML file*/
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new File("src/test/resources/SampleXPath.xml"));

        /* Create and configure parameter resolver */
        String bid = "bk102";
        SimpleVariableResolver variableResolver = new SimpleVariableResolver();
        variableResolver.addVariable(new QName("bookId"), bid);

        /*Create and configure XPATH expression*/
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(variableResolver);
        XPathExpression xPathExpression = xpath.compile("//book[@id=$bookId]");

        /* Apply expression on XML document */
        Object nodes = xPathExpression.evaluate(doc, XPathConstants.NODESET);
        NodeList nodesList = (NodeList) nodes;
        Assert.assertNotNull(nodesList);
        Assert.assertEquals(1, nodesList.getLength());
        Element book = (Element) nodesList.item(0);
        Assert.assertTrue(book.getTextContent().contains("Ralls, Kim"));
    }
}
