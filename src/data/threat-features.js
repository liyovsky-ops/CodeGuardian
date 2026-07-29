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
};
