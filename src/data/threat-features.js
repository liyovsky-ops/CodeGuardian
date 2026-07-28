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
};

// threatId -> quiz YAML data. Populated in a later phase; quizzes may exist
// for threats that have no deep-dive, so this is intentionally a separate
// map, not nested under DEEPDIVES.
export const QUIZZES = {};
