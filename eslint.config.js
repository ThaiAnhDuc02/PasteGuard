// ESLint flat config (ESLint 9+). `--ext` is gone; file globs live here.
import tsPlugin from '@typescript-eslint/eslint-plugin'
import tsParser from '@typescript-eslint/parser'
import reactHooks from 'eslint-plugin-react-hooks'
import prettier from 'eslint-config-prettier'

export default [
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**'] },

  ...tsPlugin.configs['flat/recommended'],

  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    // eslint-plugin-react is omitted: it does not support ESLint 10 (it was the
    // reason for --legacy-peer-deps) and TypeScript already checks JSX.
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // Never log input or secrets; console.error with an error message only.
      'no-console': ['error', { allow: ['error'] }],
      'no-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-syntax': [
        'error',
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: 'Never inject HTML.' },
        { selector: "MemberExpression[property.name=/^(localStorage|sessionStorage)$/]", message: 'Do not persist user input.' },
      ],
    },
  },

  {
    files: ['src/tests/**/*.ts'],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },

  prettier,
]
