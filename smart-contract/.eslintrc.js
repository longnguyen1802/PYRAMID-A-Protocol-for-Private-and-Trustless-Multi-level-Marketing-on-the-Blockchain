module.exports = {
  env: {
    browser: false,
    es2021: true,
    node: true,
  },
  extends: ["airbnb-base", "plugin:chai-friendly/recommended", "prettier"],
  plugins: ["import", "prettier"],
  rules: {
    "import/order": [
      "error",
      {
        groups: [
          "builtin",
          "external",
          "internal",
          "parent",
          "sibling",
          "index",
          "object",
        ],
        "newlines-between": "always",
        alphabetize: { order: "asc", caseInsensitive: true },
      },
    ],
    "import/no-unresolved": "error",
    "import/no-extraneous-dependencies": ["error", { devDependencies: true }],
    "prettier/prettier": "error",
    // Your custom rules
    // Add any other rules you define here
  },
  overrides: [
    {
      files: ["*.ts"],
      rules: {
        // Disable rules from @typescript-eslint
        "@typescript-eslint/no-unnecessary-type-constraint": "off",
        '@typescript-eslint/ban-ts-comment': 'off',
        '@typescript-eslint/triple-slash-reference': 'off',
        "@typescript-eslint/ban-types": 'off'
      },
      // Remove plugin:@typescript-eslint/recommended
      extends: [],
      // Remove @typescript-eslint plugin
      plugins: [],
      // Remove @typescript-eslint/parser
      parser: undefined,
    },
    {
      files: ["*.spec.ts", "*.test.ts"],
      env: {
        mocha: true,
      },
    },
  ],
};
