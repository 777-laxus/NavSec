// =============================================================
// fingerprints.js  -  Escopo fechado de tecnologias detectadas.
// Cada entrada descreve COMO identificar a biblioteca na pagina:
//   - globals:      objetos globais que indicam a presenca da lib;
//   - versionPaths: caminhos (em window) para ler a versao em runtime;
//   - srcPattern:   regex (string) para extrair a versao do src dos <script>.
// Tudo aqui e serializavel em JSON, pois e enviado como argumento
// para a funcao injetada no MAIN world da pagina.
// =============================================================

export const FINGERPRINTS = [
  {
    id: "jquery",
    name: "jQuery",
    globals: ["jQuery", "$"],
    versionPaths: ["jQuery.fn.jquery", "$.fn.jquery"],
    srcPattern: "jquery[.-]?v?(\\d+\\.\\d+\\.\\d+)",
  },
  {
    id: "angularjs",
    name: "AngularJS",
    globals: ["angular"],
    versionPaths: ["angular.version.full"],
    srcPattern: "angular(?:\\.min)?[.-]?(\\d+\\.\\d+\\.\\d+)",
  },
  {
    id: "vue",
    name: "Vue.js",
    globals: ["Vue"],
    versionPaths: ["Vue.version"],
    srcPattern: "vue(?:@|[.-])(\\d+\\.\\d+\\.\\d+)",
  },
  {
    id: "lodash",
    name: "Lodash",
    globals: ["_"],
    versionPaths: ["_.VERSION"],
    srcPattern: "lodash(?:@|[.-])(\\d+\\.\\d+\\.\\d+)",
  },
  {
    id: "moment",
    name: "Moment.js",
    globals: ["moment"],
    versionPaths: ["moment.version"],
    srcPattern: "moment(?:@|[.-])(\\d+\\.\\d+\\.\\d+)",
  },
  {
    id: "bootstrap",
    name: "Bootstrap",
    globals: ["bootstrap"],
    versionPaths: ["bootstrap.Tooltip.VERSION", "bootstrap.Modal.VERSION"],
    srcPattern: "bootstrap(?:@|[.-])(\\d+\\.\\d+\\.\\d+)",
  },
];
