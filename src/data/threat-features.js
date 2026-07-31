// Single source of truth for "which threats have which extra features"
// (deep-dive, quiz, lab, ...). Both renderer.js (decides whether to show a
// button) and interactions.js (wires the click) import from here, so the
// two can never drift out of sync the way DEEPDIVE_THREATS/DEEPDIVE_HANDLERS
// used to before this refactor.

import sqliData from '../content/deepdives/sqli.yaml';
import nosqliData from '../content/deepdives/nosqli.yaml';
import cmdiData from '../content/deepdives/cmdi.yaml';
import ldapiData from '../content/deepdives/ldapi.yaml';
import xpathiData from '../content/deepdives/xpathi.yaml';
import sstiData from '../content/deepdives/ssti.yaml';
import logiData from '../content/deepdives/logi.yaml';
import crlfiData from '../content/deepdives/crlfi.yaml';
import hhiData from '../content/deepdives/hhi.yaml';
import emailiData from '../content/deepdives/emaili.yaml';
import csviData from '../content/deepdives/csvi.yaml';
import ormiData from '../content/deepdives/ormi.yaml';
import brokenauthData from '../content/deepdives/brokenauth.yaml';
import graphqliData from '../content/deepdives/graphqli.yaml';
import xssData from '../content/deepdives/xss.yaml';
import pathtraversalData from '../content/deepdives/pathtraversal.yaml';
import xxeData from '../content/deepdives/xxe.yaml';
import protopollutionData from '../content/deepdives/protopollution.yaml';
import jndiData from '../content/deepdives/jndi.yaml';
import promptinjectionData from '../content/deepdives/promptinjection.yaml';
import ognlData from '../content/deepdives/ognl.yaml';
import yamlinjectionData from '../content/deepdives/yamlinjection.yaml';
import htmlinjectionData from '../content/deepdives/htmlinjection.yaml';
import cstiData from '../content/deepdives/csti.yaml';
import elinjectionData from '../content/deepdives/elinjection.yaml';
import argumentinjectionData from '../content/deepdives/argumentinjection.yaml';
import evalinjectionData from '../content/deepdives/evalinjection.yaml';
import httpparameterpollutionData from '../content/deepdives/httpparameterpollution.yaml';
import xmlinjectionData from '../content/deepdives/xmlinjection.yaml';
import xsltinjectionData from '../content/deepdives/xsltinjection.yaml';
import xqueryinjectionData from '../content/deepdives/xqueryinjection.yaml';
import imapinjectionData from '../content/deepdives/imapinjection.yaml';
import jsoninjectionData from '../content/deepdives/jsoninjection.yaml';
import svginjectionData from '../content/deepdives/svginjection.yaml';

import sqliQuiz from '../content/quizzes/sqli.yaml';
import nosqliQuiz from '../content/quizzes/nosqli.yaml';
import cmdiQuiz from '../content/quizzes/cmdi.yaml';
import ldapiQuiz from '../content/quizzes/ldapi.yaml';
import xpathiQuiz from '../content/quizzes/xpathi.yaml';
import sstiQuiz from '../content/quizzes/ssti.yaml';
import logiQuiz from '../content/quizzes/logi.yaml';
import crlfiQuiz from '../content/quizzes/crlfi.yaml';
import hhiQuiz from '../content/quizzes/hhi.yaml';
import emailiQuiz from '../content/quizzes/emaili.yaml';
import csviQuiz from '../content/quizzes/csvi.yaml';
import ormiQuiz from '../content/quizzes/ormi.yaml';
import brokenauthQuiz from '../content/quizzes/brokenauth.yaml';
import graphqliQuiz from '../content/quizzes/graphqli.yaml';
import xssQuiz from '../content/quizzes/xss.yaml';
import pathtraversalQuiz from '../content/quizzes/pathtraversal.yaml';
import xxeQuiz from '../content/quizzes/xxe.yaml';
import protopollutionQuiz from '../content/quizzes/protopollution.yaml';
import jndiQuiz from '../content/quizzes/jndi.yaml';
import promptinjectionQuiz from '../content/quizzes/promptinjection.yaml';
import ognlQuiz from '../content/quizzes/ognl.yaml';
import yamlinjectionQuiz from '../content/quizzes/yamlinjection.yaml';
import htmlinjectionQuiz from '../content/quizzes/htmlinjection.yaml';
import cstiQuiz from '../content/quizzes/csti.yaml';
import elinjectionQuiz from '../content/quizzes/elinjection.yaml';
import argumentinjectionQuiz from '../content/quizzes/argumentinjection.yaml';
import evalinjectionQuiz from '../content/quizzes/evalinjection.yaml';
import httpparameterpollutionQuiz from '../content/quizzes/httpparameterpollution.yaml';
import xmlinjectionQuiz from '../content/quizzes/xmlinjection.yaml';
import xsltinjectionQuiz from '../content/quizzes/xsltinjection.yaml';
import xqueryinjectionQuiz from '../content/quizzes/xqueryinjection.yaml';
import imapinjectionQuiz from '../content/quizzes/imapinjection.yaml';
import jsoninjectionQuiz from '../content/quizzes/jsoninjection.yaml';
import svginjectionQuiz from '../content/quizzes/svginjection.yaml';

// threatId -> deep-dive YAML data (or undefined if none exists)
export const DEEPDIVES = {
  '1.1': sqliData,
  '1.2': nosqliData,
  '1.3': cmdiData,
  '1.4': ldapiData,
  '1.5': xpathiData,
  '1.6': sstiData,
  '1.7': logiData,
  '1.8': crlfiData,
  '1.9': hhiData,
  '1.10': emailiData,
  '1.11': csviData,
  '1.12': ormiData,
  '1.13': graphqliData,
  '2.1': brokenauthData,
  cat_1_research12: xssData, // XSS (Reflected/Stored/DOM/mXSS consolidated) — no clean numeric id in the catalog yet
  cat_1_research13: pathtraversalData, // Path Traversal / Directory Traversal
  cat_1_research11: xxeData, // XML External Entity (XXE) Injection
  cat_1_research18: protopollutionData, // Prototype Pollution
  cat_1_research10: jndiData, // JNDI Injection (Log4Shell)
  cat_1_research03: promptinjectionData, // Prompt Injection
  '1.17': ognlData, // OGNL Injection (Apache Struts)
  cat_1_research05: yamlinjectionData, // YAML Injection / Unsafe Deserialization
  '1.24': htmlinjectionData, // HTML Injection
  cat_1_research01: cstiData, // Client-Side Template Injection (CSTI)
  '1.16': elinjectionData, // Expression Language Injection (Java EL / Spring SpEL)
  cat_1_research08: argumentinjectionData, // Argument Injection
  '1.20': evalinjectionData, // Code Injection (merged with Eval Injection -- see 1.23's catalog note)
  '1.26': httpparameterpollutionData, // HTTP Parameter Pollution (merged with HTTP Parameter Injection -- see cat_1_research21's catalog note)
  '1.28': xmlinjectionData, // XML Injection (generic markup injection + XSW, distinct from XXE/XPath)
  cat_1_research02: xsltinjectionData, // XSLT Injection (merged with XSL Injection -- see cat_1_research17's catalog note)
  '1.19': xqueryinjectionData, // XQuery Injection
  '1.27': imapinjectionData, // IMAP Injection
  cat_1_research06: jsoninjectionData, // JSON Injection (structural + polymorphic deserialization)
  cat_1_research14: svginjectionData, // SVG Injection (SVG-based XSS via file upload)
};

// threatId -> quiz YAML data. Quizzes may exist for threats that have no
// deep-dive, so this is intentionally a separate map, not nested under
// DEEPDIVES.
export const QUIZZES = {
  '1.1': sqliQuiz,
  '1.2': nosqliQuiz,
  '1.3': cmdiQuiz,
  '1.4': ldapiQuiz,
  '1.5': xpathiQuiz,
  '1.6': sstiQuiz,
  '1.7': logiQuiz,
  '1.8': crlfiQuiz,
  '1.9': hhiQuiz,
  '1.10': emailiQuiz,
  '1.11': csviQuiz,
  '1.12': ormiQuiz,
  '1.13': graphqliQuiz,
  '2.1': brokenauthQuiz,
  cat_1_research12: xssQuiz,
  cat_1_research13: pathtraversalQuiz,
  cat_1_research11: xxeQuiz,
  cat_1_research18: protopollutionQuiz,
  cat_1_research10: jndiQuiz,
  cat_1_research03: promptinjectionQuiz,
  '1.17': ognlQuiz,
  cat_1_research05: yamlinjectionQuiz,
  '1.24': htmlinjectionQuiz,
  cat_1_research01: cstiQuiz,
  '1.16': elinjectionQuiz,
  cat_1_research08: argumentinjectionQuiz,
  '1.20': evalinjectionQuiz,
  '1.26': httpparameterpollutionQuiz,
  '1.28': xmlinjectionQuiz,
  cat_1_research02: xsltinjectionQuiz,
  '1.19': xqueryinjectionQuiz,
  '1.27': imapinjectionQuiz,
  cat_1_research06: jsoninjectionQuiz,
  cat_1_research14: svginjectionQuiz,
};
