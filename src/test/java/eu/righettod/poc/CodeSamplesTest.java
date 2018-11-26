package eu.righettod.poc;

import com.mongodb.Block;
import com.mongodb.MongoClient;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoDatabase;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.conversions.Bson;
import org.junit.Assert;
import org.junit.Test;
import org.owasp.encoder.Encode;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXParseException;

import javax.persistence.EntityManager;
import javax.persistence.Persistence;
import javax.persistence.Query;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static com.mongodb.client.model.Filters.eq;

/**
 * Contains all samples of code used into the README.md file.
 */
public class CodeSamplesTest {

    /**
     * Sample for NoSQL injection prevention, here using MongoDB as target NoSQL DB.
     * <p>
     * Use the following link to setup the test database: https://docs.mongodb.com/getting-started/java/import-data/#procedure
     */
    @Test
    public void testSampleNoSQLInjection() {

        /* Here use MongoDB as target NoSQL DB */
        String userInput = "Brooklyn";

        /* First ensure that the input do no contains any special characters for the current NoSQL DB call API, here they are: ' " \ ; { } $*/
        //Avoid regexp this time in order to made validation code more easy to read and understand...
        ArrayList<String> specialCharsList = new ArrayList<String>() {{
            add("'");
            add("\"");
            add("\\");
            add(";");
            add("{");
            add("}");
            add("$");
        }};
        specialCharsList.forEach(specChar -> Assert.assertFalse(userInput.contains(specChar)));
        //Add also a check on input max size
        Assert.assertTrue(userInput.length() <= 50);

        /* Then perform query on database using API to build expression */
        //Connect to the local MongoDB instance
        try (MongoClient mongoClient = new MongoClient()) {
            MongoDatabase db = mongoClient.getDatabase("test");
            //Use API query builder to create call expression
            //Create expression
            Bson expression = eq("borough", userInput);
            //Perform call
            FindIterable<org.bson.Document> restaurants = db.getCollection("restaurants").find(expression);
            //Verify result consistency
            restaurants.forEach(new Block<org.bson.Document>() {
                @Override
                public void apply(final org.bson.Document doc) {
                    String restBorough = (String) doc.get("borough");
                    Assert.assertTrue("Brooklyn".equals(restBorough));
                }
            });
        }

    }

    /**
     * Sample for HTML/JS/CSS injection prevention.
     */
    @Test
    public void testSampleHTMLCSSJSInjection() {
        /*
        INPUT WAY: Receive data from user
        Here it's recommended to use strict input validation using whitelist approach.
        In fact, you ensure that only allowed characters are part of the input received.
        */

        String userInput = "You user login is owasp-user01";

        /* First we check that the value contains only expected character*/
        Assert.assertTrue(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput));

        /* If the first check pass then ensure that potential dangerous character that we have allowed
        for business requirement are not used in a dangerous way.
        For example here we have allowed the character '-', and, this can be used in SQL injection so, we
        ensure that this character is not used is a continuous form.
        Use the API COMMONS LANG v3 to help in String analysis...
        */
        Assert.assertEquals(0, StringUtils.countMatches(userInput.replace(" ", ""), "--"));

        /*
        OUTPUT WAY: Send data to user
        Here we escape + sanitize any data sent to user
        Use the OWASP Java HTML Sanitizer API to handle sanitizing
        Use the OWASP Java Encoder API to handle HTML tag encoding (escaping)
         */

        String outputToUser = "You <p>user login</p> is <strong>owasp-user01</strong>";
        outputToUser += "<script>alert(22);</script><img src='#' onload='javascript:alert(23);'>";

        /* Create a sanitizing policy that only allow tag '<p>' and '<strong>'*/
        PolicyFactory policy = new HtmlPolicyBuilder().allowElements("p", "strong").toFactory();

        /* Sanitize the output that will be sent to user*/
        String safeOutput = policy.sanitize(outputToUser);

        /* Encode HTML Tag*/
        safeOutput = Encode.forHtml(safeOutput);
        String finalSafeOutputExpected = "You &lt;p&gt;user login&lt;/p&gt; is &lt;strong&gt;owasp-user01&lt;/strong&gt;";
        Assert.assertEquals(finalSafeOutputExpected, safeOutput);
    }

    /**
     * Sample for SQL query injection prevention
     *
     * @throws Exception Global error
     */
    @Test
    public void testSampleSQLQuery() throws Exception {
        /*No framework used here in order to show the real use of Prepared Statement*/


        /*Open connection with H2 database and use it*/
        Class.forName("org.h2.Driver");
        String jdbcUrl = "jdbc:h2:file:" + new File(".").getAbsolutePath() + "/target/db";
        try (Connection con = DriverManager.getConnection(jdbcUrl)) {

            /* Sample A: Select data using Prepared Statement*/
            String query = "select * from color where friendly_name = ?";
            List<String> colors = new ArrayList<>();
            try (PreparedStatement pStatement = con.prepareStatement(query)) {
                pStatement.setString(1, "yellow");
                try (ResultSet rSet = pStatement.executeQuery()) {
                    while (rSet.next()) {
                        colors.add(rSet.getString(1));
                    }
                }
            }
            Assert.assertEquals(1, colors.size());
            Assert.assertTrue(colors.contains("yellow"));

            /* Sample B: Insert data using Prepared Statement*/
            query = "insert into color(friendly_name, red, green, blue) values(?, ?, ?, ?)";
            int insertedRecordCount;
            try (PreparedStatement pStatement = con.prepareStatement(query)) {
                pStatement.setString(1, "orange");
                pStatement.setInt(2, 239);
                pStatement.setInt(3, 125);
                pStatement.setInt(4, 11);
                insertedRecordCount = pStatement.executeUpdate();
            }
            Assert.assertEquals(1, insertedRecordCount);

            /* Sample C: Update data using Prepared Statement*/
            query = "update color set blue = ? where friendly_name = ?";
            int updatedRecordCount;
            try (PreparedStatement pStatement = con.prepareStatement(query)) {
                pStatement.setInt(1, 10);
                pStatement.setString(2, "orange");
                updatedRecordCount = pStatement.executeUpdate();
            }
            Assert.assertEquals(1, updatedRecordCount);

            /* Sample D: Delete data using Prepared Statement*/
            query = "delete from color where friendly_name = ?";
            int deletedRecordCount;
            try (PreparedStatement pStatement = con.prepareStatement(query)) {
                pStatement.setString(1, "orange");
                deletedRecordCount = pStatement.executeUpdate();
            }
            Assert.assertEquals(1, deletedRecordCount);

        }
    }

    /**
     * Sample for Operating System command injection prevention
     *
     * @throws Exception Global error
     */
    @Test
    public void testSampleOSCmd() throws Exception {
        /* The context taken is, for example, to perform a PING against a computer.
         * The prevention is to use the feature provided by the Java API instead of building
         * a system command as String and execute it */
        InetAddress host = InetAddress.getByName("localhost");
        Assert.assertTrue(host.isReachable(5000));
    }


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
    public void testSampleXPathQuery() throws Exception {
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

    /**
     * Sample for JPA QL query injection prevention.
     *
     * @throws Exception Global error
     */
    @Test
    public void testSampleJPAQLQuery() throws Exception {
        EntityManager entityManager = null;
        try {
            /* Get a ref on EntityManager to access DB */
            entityManager = Persistence.createEntityManagerFactory("testJPA").createEntityManager();

            /* Define parametrized query prototype using named parameter to enhance readability */
            String queryPrototype = "select c from Color c where c.friendlyName = :colorName";

            /* Create the query, set parameter and execute the query */
            Query queryObject = entityManager.createQuery(queryPrototype);
            Color c = (Color) queryObject.setParameter("colorName", "yellow").getSingleResult();

            /*Ensure the result*/
            Assert.assertNotNull(c);
            Assert.assertEquals(c.getFriendlyName(), "yellow");
            Assert.assertEquals(c.getRed(), 213);
            Assert.assertEquals(c.getGreen(), 242);
            Assert.assertEquals(c.getBlue(), 26);
        } finally {
            if (entityManager != null && entityManager.isOpen()) {
                entityManager.close();
            }
        }
    }

    /**
     * Sample for Log injection prevention.
     *
     * @throws Exception Global error
     */
    @Test
    public void testSampleLogInjection() throws Exception {
        /* Prepare the logger and the payload */
        Path logFile = Paths.get("App.log");
        Logger logger = LogManager.getLogger(CodeSamplesTest.class);
        String padding = StringUtils.repeat("X", 10000);
        String payload = "\n\rMY\r\nSPLITTED\n\rPAYLOAD\n\r" + padding;
        /* Log the payload */
        logger.info(payload);
        /* Ensure that the payload is neutralised */
        List<String> logLines = Files.readAllLines(logFile);
        Assert.assertEquals(1, logLines.size());
        String log = logLines.get(0);
        String expected = "\\n\\rMY\\r\\nSPLITTED\\n\\rPAYLOAD\\n\\rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        Assert.assertEquals(expected, log);
    }

}
