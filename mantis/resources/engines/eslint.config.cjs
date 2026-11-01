// Mantis-owned ESLint config. Passed with -c so the audited tree's own
// eslint.config.* (which is code, and may load plugins) is never evaluated.
// eslint-plugin-security resolves via NODE_PATH from the global install.
const security = require("eslint-plugin-security");

module.exports = [
  security.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
  },
];
