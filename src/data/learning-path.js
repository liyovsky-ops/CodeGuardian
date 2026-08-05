// Ordered progression track through the threats that have practice content
// (a quiz — the only automatically-verifiable signal we have). Order goes
// from the most fundamental / highest-prevalence classes to more niche or
// newer ones, so the path doesn't force jumping to an exotic variant before
// the basics: classic injection + auth first, specialized injection
// sub-types next, GraphQL (newest attack surface) last.
export const LEARNING_PATH = [
  '1.1', // SQL Injection
  '1.3', // Command Injection
  '2.1', // Broken Authentication
  'cat_1_research12', // Cross-Site Scripting (XSS)
  'cat_1_research13', // Path Traversal / Directory Traversal
  'cat_1_research11', // XML External Entity (XXE) Injection
  'cat_1_research18', // Prototype Pollution
  'cat_1_research10', // JNDI Injection (Log4Shell)
  'cat_1_research03', // Prompt Injection
  '1.17', // OGNL Injection (Apache Struts)
  'cat_1_research05', // YAML Injection / Unsafe Deserialization
  '1.24', // HTML Injection
  'cat_1_research01', // Client-Side Template Injection (CSTI)
  '1.16', // Expression Language Injection (Java EL / Spring SpEL)
  'cat_1_research08', // Argument Injection
  '1.20', // Code Injection / Eval Injection (merged; 1.23 is the same threat, cross-referenced)
  '1.26', // HTTP Parameter Pollution (merged; cat_1_research21 is the same threat, cross-referenced)
  '1.28', // XML Injection (generic markup injection + XSW, distinct from XXE/XPath)
  'cat_1_research02', // XSLT Injection (merged; cat_1_research17 is the same threat, cross-referenced)
  '1.19', // XQuery Injection
  '1.27', // IMAP Injection
  'cat_1_research06', // JSON Injection (structural + polymorphic deserialization)
  'cat_1_research14', // SVG Injection (SVG-based XSS via file upload)
  'cat_1_research16', // Regex Injection / ReDoS
  'cat_1_research22', // Perl open() Injection
  'cat_1_research25', // Null Byte Injection
  'cat_1_research27', // SPARQL Injection
  'cat_1_research28', // PDF Injection
  'cat_1_research29', // OData Injection
  '15.1', // Improper Credential Usage (Mobile) -- first Mobile Security entry
  '15.2', // Inadequate Supply Chain Security (Mobile)
  '15.3', // Insecure Authentication/Authorization (Mobile)
  '15.4', // Insufficient Input/Output Validation (Mobile)
  '15.5', // Insecure Communication (Mobile)
  '15.6', // Inadequate Privacy Controls (Mobile)
  '15.7', // Insufficient Binary Protections (Mobile)
  '15.8', // Security Misconfiguration (Mobile)
  '15.9', // Insecure Data Storage (Mobile)
  '1.2', // NoSQL Injection
  '1.6', // Server-Side Template Injection
  '1.4', // LDAP Injection
  '1.5', // XPath Injection
  '1.7', // Log Injection
  '1.8', // CRLF Injection
  '1.9', // HTTP Header Injection
  '1.10', // Email/SMTP Injection
  '1.11', // CSV Injection
  '1.12', // ORM Injection
  '1.13', // GraphQL Injection
];
