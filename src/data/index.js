import { CAT_INJECTION }    from './cat_01_injection.js';
import { CAT_AUTH }         from './cat_02_auth.js';
import { CAT_CRYPTO }       from './cat_03_cryptography.js';
import { CAT_DATA }         from './cat_04_data_exposure.js';
import { CAT_INPUT }        from './cat_05_input_validation.js';
import { CAT_SUPPLY }       from './cat_06_supply_chain.js';
import { CAT_CONFIG }       from './cat_07_configuration.js';
import { CAT_LOGIC }        from './cat_08_business_logic.js';
import { CAT_INFRA }        from './cat_09_infrastructure.js';
import { CAT_API }          from './cat_10_api_security.js';
import { CAT_AI }           from './cat_11_ai_llm.js';
import { CAT_MEMORY }       from './cat_12_memory_safety.js';
import { CAT_DESERIALIZE }  from './cat_13_deserialization.js';
import { CAT_DOS }          from './cat_14_dos.js';

export const CATEGORIES = [
  CAT_INJECTION, CAT_AUTH, CAT_CRYPTO, CAT_DATA,
  CAT_INPUT, CAT_SUPPLY, CAT_CONFIG, CAT_LOGIC,
  CAT_INFRA, CAT_API, CAT_AI, CAT_MEMORY, CAT_DESERIALIZE, CAT_DOS,
];
