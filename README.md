# Introduction

This document has for objective to provide some tips to handle **Injection** into application code.

It's a work in progress in order to create a cheat sheets about Injection topic with OWASP Java folks.

TODO:
* Add code for all
* Add NoSQL / LDAP

# What is Injection ?

[Injection](https://www.owasp.org/index.php/Top_10_2013-A1-Injection) in OWASP Top 10 is defined as following:

"Consider anyone who can send untrusted data to the system, including external users, internal users, and administrators."

# General advices to prevent Injection

The following point can be applied, in a general way, to prevent **Injection** issue:

1. When possible, apply *Input Validation* on user input using whitelist approach.
2. If you need to interact with system, try to use API features provided by your technology stack (Java / .Net / PHP...) instead of building command.

# Specific Injection types

*Examples in this section will be provided in Java technology (see Maven project associated) but advices are applicable to others technologies like .Net / PHP / Ruby / Python...*

## SQL

### Symptom

Injection of this type occur when the application use untrusted user input to build a SQL query using a String and execute it.

### How to prevent

Use **Prepared Statment** in order to prevent injection.

### Example

TODO

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

TODO

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

    private static final Map<QName, Object> vars = new HashMap<QName, Object>();

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
Assert.assertEquals(1,nodesList.getLength());
```

### References

https://www.owasp.org/index.php/XPATH_Injection

## HTML/JavaScript/CSS

### Symptom

Injection of this type occur when the application use untrusted user input to build a HTTP response and sent it to browser.

### How to prevent

Either apply strict input validation (whitelist approach) or use output escaping if input validation is not possible (use both is possible).

### Example

TODO

### References

https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
