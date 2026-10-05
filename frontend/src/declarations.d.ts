declare module "*.css";

declare namespace React {
  interface InputHTMLAttributes<T> {
    webkitdirectory?: string;
    directory?: string;
  }
}

interface ImportMetaEnv {
  readonly VITE_DETECTION_ANALYSIS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
