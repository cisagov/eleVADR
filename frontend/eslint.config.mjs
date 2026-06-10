import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactPlugin from "eslint-plugin-react";
import hooksPlugin from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  // 1. Ignore build folders and config files
  { ignores: ["dist", "node_modules", "build"] },

  // 2. Base JS and TS configurations
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // 3. React and Hooks Configuration
  {
    files: ["**/*.{ts,tsx,js,jsx}"],
    plugins: {
      react: reactPlugin,
      "react-hooks": hooksPlugin,
    },
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
    rules: {
      // React 19 doesn't require React to be in scope, so disable this
      "react/react-in-jsx-scope": "off",

      // Use the recommended hooks rules
      ...hooksPlugin.configs.recommended.rules,

      // Example: prevent unused variables (warn instead of error)
      "@typescript-eslint/no-unused-vars": "warn",
    },
    settings: {
      react: {
        version: "detect", // Automatically detects React 19
      },
    },
  },
);
