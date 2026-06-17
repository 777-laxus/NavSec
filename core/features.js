// =============================================================
// features.js  -  Registro central das features da extensao.
// A ordem do array define a navegacao circular (chevrons/dots).
// Para adicionar uma nova tela no futuro, basta criar a feature
// e incluir aqui - o nucleo nao precisa de outras alteracoes.
// =============================================================

import { stacksFeature } from "../features/stacks/stacks.feature.js";
import { jsvulnFeature } from "../features/jsvuln/jsvuln.feature.js";
import { reputationFeature } from "../features/reputation/reputation.feature.js";

export const FEATURES = [stacksFeature, jsvulnFeature, reputationFeature];
