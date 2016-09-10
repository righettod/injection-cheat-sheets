# Introduction

This document has for objective to provide some tips to handle **Injection** into application code.

It's a work in progress in order to create a cheat sheets about Injection topic with OWASP Java folks.

# Roadmap

* Add code samples for all specific injection
* Add NoSQL / LDAP case

*Code of samples are implemented using Maven test cases.*

# What is Injection ?

[Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection) in OWASP Top 10 is defined as following:

"Consider anyone who can send untrusted data to the system, including external users, internal users, and administrators."

# General advices to prevent Injection

The following point can be applied, in a general way, to prevent **Injection** issue:

1. Apply *Input Validation* (using whitelist approach) combined with *Output Sanitizing+Escaping* on user input/output.
2. If you need to interact with system, try to use API features provided by your technology stack (Java / .Net / PHP...) instead of building command.

# Specific Injection types

*Examples in this section will be provided in Java technology (see Maven project associated) but advices are applicable to others technologies like .Net / PHP / Ruby / Python...*

## SQL

### Symptom

Injection of this type occur when the application use untrusted user input to build a SQL query using a String and execute it.

### How to prevent

Use **Prepared Statement** in order to prevent injection.

### Example

```java
/*No DB framework used here in order to show the real use of Prepared Statement from Java API*/
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
```

### References

https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet

## JPA

### Symptom

Injection of this type occur when the application use untrusted user input to build a JPA query using a String and execute it.

### How to prevent

Use **Java Persistence Query Language** in order to prevent injection.

### Example

TODO

## Operating System

### Symptom

Injection of this type occur when the application use untrusted user input to build a Operating System command using a String and execute it.

### How to prevent

Use technology stack **API** in order to prevent injection.

### Example

```java
/* The context taken is, for example, to perform a PING against a computer.
* The prevention is to use the feature provided by the Java API instead of building
* a system command as String and execute it */
InetAddress host = InetAddress.getByName("localhost");
Assert.assertTrue(host.isReachable(5000));
```

### References

https://www.owasp.org/index.php/Command_Injection

## XML: External Entity attack

### Symptom

Injection of this type occur when the application load the received XML stream using a XML parser instance in which the resolution of External Entity is not disabled.

### How to prevent

Disable to resolution of the External Entity in the parser instance to prevent injection.

### Example

```java
/*Create a XML document builder factory*/
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

/*Disable External Entity resolution for differents cases*/
// This is the PRIMARY defense. If DTDs (doctypes) are disallowed, 
// almost all XML entity attacks are prevented
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

// and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

/*Load XML file*/
DocumentBuilder builder = dbf.newDocumentBuilder();
//Here an org.xml.sax.SAXParseException will be throws because the XML contains a External Entity.
builder.parse(new File("src/test/resources/SampleXXE.xml"));
```

## XML: XPath Injection

### Symptom

Injection of this type occur when the application use untrusted user input to build a XPath query using a String and execute it.

### How to prevent

Use **XPath Variable Resolver** in order to prevent injection.

### Example

*Variable Resolver* implementation

```java
/**
 * Resolver in order to define parameter for XPATH expression.
 *
 */
public class SimpleVariableResolver implements XPathVariableResolver {

    private final Map<QName, Object> vars = new HashMap<QName, Object>();

    /**
     * External methods to add parameter
     *
     * @param name Parameter name
     * @param value Parameter value
     */
    public void addVariable(QName name, Object value) {
        vars.put(name, value);
    }

    /**
     * {@inheritDoc}
     *
     * @see javax.xml.xpath.XPathVariableResolver#resolveVariable(javax.xml.namespace.QName)
     */
    public Object resolveVariable(QName variableName) {
        return vars.get(variableName);
    }
}
```

Code using it to perform XPath query

```java
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
Element book = (Element)nodesList.item(0);
Assert.assertTrue(book.getTextContent().contains("Ralls, Kim"));
```

### References

https://www.owasp.org/index.php/XPATH_Injection

## HTML/JavaScript/CSS

### Symptom

Injection of this type occur when the application use untrusted user input to build a HTTP response and sent it to browser.

### How to prevent

Either apply strict input validation (whitelist approach) or use output sanitizing+escaping if input validation is not possible (combine both every time is possible).

### Example

```java
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
Use the API COMMONS LANG v3 to help in HTML tag encoding (escaping)
 */

String outputToUser = "You <p>user login</p> is <strong>owasp-user01</strong>";
outputToUser += "<script>alert(22);</script><img src='#' onload='javascript:alert(23);'>";

/* Create a sanitizing policy that only allow tag '<p>' and '<strong>'*/
PolicyFactory policy = new HtmlPolicyBuilder().allowElements("p","strong").toFactory();

/* Sanitize the output that will be sent to user*/
String safeOutput = policy.sanitize(outputToUser);

/* Encode HTML Tag*/
safeOutput = StringEscapeUtils.escapeHtml3(safeOutput);
safeOutput = StringEscapeUtils.escapeHtml4(safeOutput);
String finalSafeOutputExpected = "You &amp;lt;p&amp;gt;user login&amp;lt;/p&amp;gt; is ";
finalSafeOutputExpected += "&amp;lt;strong&amp;gt;owasp-user01&amp;lt;/strong&amp;gt;";
Assert.assertEquals(finalSafeOutputExpected, safeOutput);
```

### References

https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
https://github.com/owasp/java-html-sanitizer
https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html
https://commons.apache.org/proper/commons-lang/javadocs/api-3.4/org/apache/commons/lang3/StringEscapeUtils.html

## NoSQL

### Symptom

Injection of this type occur when the application use untrusted user input to build a NoSQL API call expression.

### How to prevent

As there many NoSQL database system and each one use a API for call, it's important to ensure that user input received 
and used to build the API call expression do not contains any character that have a special meaning in the target API syntax.
This in order to avoid that it will be used to escape the initial call expression in order to create another one based on crafted user input.
It's also important to not use string concatenation to build API call expression but use the API to create the expression.

### Example

```java
 /* Here use MongoDB as target NoSQL DB */
String userInput = "Brooklyn";

/* First ensure that the input do no contains any special characters for the current NoSQL DB call API, 
here they are: ' " \ ; { } 
*/
//Avoid regexp this time in order to made validation code more easy to read and understand...
ArrayList<String> specialCharsList = new ArrayList<String>() {{
    add("'");
    add("\"");
    add("\\");
    add(";");
    add("{");
    add("}");
}};
specialCharsList.forEach(specChar -> Assert.assertFalse(userInput.contains(specChar)));
//Add also a check on input max size
Assert.assertTrue(userInput.length() <= 50);

/* Then perform query on database using API to build expression */
//Connect to the local MongoDB instance
try(MongoClient mongoClient = new MongoClient()){
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
            String restBorough = (String)doc.get("borough");
            Assert.assertTrue("Brooklyn".equals(restBorough));
        }
    });
}
```

### References

https://www.owasp.org/index.php/Testing_for_NoSQL_injection
https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_sql_and_nosql_injection.html
https://arxiv.org/ftp/arxiv/papers/1506/1506.04082.pdf
