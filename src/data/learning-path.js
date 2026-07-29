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
