import { z } from 'zod';

// A bilingual text block, present everywhere in the deep-dive YAML.
const BilingualString = z.object({
  en: z.string().min(1),
  pl: z.string().min(1),
});

// A heading + (optional) lead intro shared by most sections.
const sectionHeader = {
  title: BilingualString,
  lead: BilingualString.optional(),
};

// External link used in hero.sources, sections.sources, *.inlineSources.
const SourceLink = z.object({
  label: z.string().min(1),
  url: z.string().url(),
});

// --- meta ------------------------------------------------------------------
const MetaSchema = z.object({
  id: z.string().min(1),
  threatId: z.string().min(1),
  severity: z.enum(['Critical', 'High', 'Medium', 'Low']),
  color: z.string().regex(/^#[0-9a-f]{6}$/i, 'must be a #rrggbb hex color'),
  colorRgb: z.string().regex(/^\d{1,3},\d{1,3},\d{1,3}$/, 'must be "r,g,b"'),
  cwe: z.string().min(1),
  cvss: z.string().min(1),
  standard: z.string().min(1),
});

// --- hero ------------------------------------------------------------------
const MetricSchema = z.object({
  k: z.string().min(1),
  // "v" is either a bilingual block or a plain string (e.g. "CVSS · Critical").
  v: z.union([BilingualString, z.string().min(1)]),
});

const HeroSchema = z.object({
  titleMain: z.string().min(1),
  titleGrad: z.string().min(1),
  titleTail: z.string(), // can be empty ("")
  topbar: z.string().min(1),
  lead: BilingualString,
  metrics: z.array(MetricSchema).min(1),
  sources: z.array(SourceLink).min(1),
});

// --- nav / sectionOrder ----------------------------------------------------
const NavItemSchema = z.object({
  id: z.string().min(1),
  en: z.string().min(1),
  pl: z.string().min(1),
});

// --- sections --------------------------------------------------------------
const AttacksSchema = z.object({
  ...sectionHeader,
  items: z.array(z.object({
    name: z.string().min(1),
    sev: z.string().min(1),
    description: BilingualString,
    payload: z.string().min(1),
  })).min(1),
});

const CheatsheetSchema = z.object({
  ...sectionHeader,
  groups: z.array(z.object({
    name: z.string().min(1),
    rows: z.array(z.array(z.string())),
  })).min(1),
});

const CodeSchema = z.object({
  ...sectionHeader,
  languages: z.array(z.object({
    label: z.string().min(1),
    lang: z.string().min(1),
    vulnerable: z.string().min(1),
    safe: z.string().min(1),
  })).min(1),
});

// langRisks and orm share the same shape (framework + raw-escape-hatch API).
const FrameworkRiskSchema = z.object({
  ...sectionHeader,
  rows: z.array(z.object({
    fw: z.string().min(1),
    api: z.string().min(1),
    note: BilingualString,
  })).min(1),
});

const MethodSchema = z.object({
  ...sectionHeader,
  steps: z.array(z.object({
    title: BilingualString,
    description: BilingualString,
  })).min(1),
});

const DefensesSchema = z.object({
  ...sectionHeader,
  items: z.array(z.object({
    rank: z.number().int(),
    eff: z.number().int().min(0).max(100),
    kind: z.string().min(1),
    label: BilingualString,
    note: BilingualString,
  })).min(1),
});

const IncidentsSchema = z.object({
  ...sectionHeader,
  items: z.array(z.object({
    org: z.string().min(1),
    year: z.number().int(),
    impact: z.string().min(1),
    cost: z.string().min(1),
    description: BilingualString,
  })).min(1),
  inlineSources: z.array(SourceLink).optional(),
});

const ToolsSchema = z.object({
  ...sectionHeader,
  sast: z.array(z.array(z.string())).min(1),
  dast: z.array(z.array(z.string())).min(1),
  note: BilingualString.optional(),
});

const ComplianceSchema = z.object({
  ...sectionHeader,
  items: z.array(z.object({
    std: z.string().min(1),
    items: z.array(z.string().min(1)).min(1),
  })).min(1),
  inlineSources: z.array(SourceLink).optional(),
});

const IrSchema = z.object({
  ...sectionHeader,
  steps: z.array(BilingualString).min(1),
});

const MigrationSchema = z.object({
  ...sectionHeader,
  steps: z.array(z.object({
    title: BilingualString,
    description: BilingualString,
  })).min(1),
});

// sections.sources: a titled list of links (no lead).
const SourcesSectionSchema = z.object({
  title: BilingualString,
  items: z.array(SourceLink).min(1),
});

const SectionsSchema = z.object({
  attacks: AttacksSchema.optional(),
  cheatsheet: CheatsheetSchema.optional(),
  code: CodeSchema.optional(),
  orm: FrameworkRiskSchema.optional(),
  langRisks: FrameworkRiskSchema.optional(),
  method: MethodSchema.optional(),
  defenses: DefensesSchema.optional(),
  incidents: IncidentsSchema.optional(),
  tools: ToolsSchema.optional(),
  compliance: ComplianceSchema.optional(),
  ir: IrSchema.optional(),
  migration: MigrationSchema.optional(),
  sources: SourcesSectionSchema.optional(),
});

// --- root ------------------------------------------------------------------
export const DeepDiveSchema = z.object({
  meta: MetaSchema,
  hero: HeroSchema,
  sectionOrder: z.array(z.string().min(1)).min(1),
  nav: z.array(NavItemSchema).min(1),
  sections: SectionsSchema,
});

export default DeepDiveSchema;
