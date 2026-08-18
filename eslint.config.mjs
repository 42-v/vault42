// Vault42 — ESLint flat config (ESLint v9+)
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import vue from 'eslint-plugin-vue';
import vueParser from 'vue-eslint-parser';
import globals from 'globals';

export default [
  // Ignore generated / vendored output
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      'web/dist/**',
      'packages/vue/dist/**',
      'internal/frontend/dist/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...vue.configs['flat/recommended'],

  {
    files: ['**/*.{js,ts,tsx,vue}'],
    languageOptions: {
      parser: vueParser,
      parserOptions: {
        parser: tseslint.parser,
        ecmaVersion: 'latest',
        sourceType: 'module',
        extraFileExtensions: ['.vue'],
      },
      globals: {
        ...globals.browser,
        ...globals.es2025,
      },
    },
    rules: {
      // Stylistic preferences
      'vue/multi-word-component-names': 'off',           // single-word view names (Home, Login) are fine
      'vue/html-self-closing': ['warn', {                // be permissive on HTML self-close style
        html: { void: 'always', normal: 'any', component: 'always' },
      }],
      'vue/max-attributes-per-line': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-indent': ['warn', 2],

      // TS — pragmatic
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
        caughtErrorsIgnorePattern: '^_',
      }],
      '@typescript-eslint/no-explicit-any': 'off',       // Vault42 talks JSON; sometimes any is right
      '@typescript-eslint/no-empty-function': 'off',
      '@typescript-eslint/ban-ts-comment': ['warn', {
        'ts-expect-error': 'allow-with-description',
        'ts-ignore': 'allow-with-description',
      }],

      // Modern JS hygiene
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'no-debugger': 'error',
      'eqeqeq': ['error', 'always', { null: 'ignore' }],
      'prefer-const': 'warn',
      'no-var': 'error',
    },
  },

  // Test files: relax stricter rules
  {
    files: ['**/__tests__/**/*.{ts,tsx,vue}', '**/*.{test,spec}.{ts,tsx}'],
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.browser,
      },
    },
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      // vue/one-component-per-file is an SFC authoring rule: it exists so a .vue
      // file resolves to one component. A .ts spec that calls defineComponent
      // several times is building stubs and route targets, which is the whole
      // point of the file — there is no second component for a reader to be
      // surprised by, and no .vue file to split it into.
      'vue/one-component-per-file': 'off',
    },
  },

  // Config files
  {
    files: ['*.config.{js,mjs,ts}', '*.cjs'],
    languageOptions: {
      globals: globals.node,
    },
  },
];
