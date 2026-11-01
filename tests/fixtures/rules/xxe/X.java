class X {
  void vuln() throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // ruleid: spring-a03-xxe-sax-parser-newinstance-call-site
    DocumentBuilder db = dbf.newDocumentBuilder();                     // ruleid: spring-a03-xxe-sax-parser-no-protection
  }
  void hardened() throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); // ok
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder db = dbf.newDocumentBuilder();                     // ok
  }
  void hardenedSax() throws Exception {
    SAXParserFactory spf = SAXParserFactory.newInstance();             // ok
    spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    SAXParser p = spf.newSAXParser();                                  // ok
  }
}
