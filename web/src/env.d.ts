/// <reference types="vite/client" />
// The suites under src/__tests__ read the tree -- the palette out of style.css,
// the CSP out of nginx.conf, the locale files off disk -- so they import
// node:fs, node:url and node:path, and those are ambient declarations that have
// to be pulled in rather than resolved.
//
// This was never declared. `@types/node` reached the program as a transitive of
// `@types/qrcode`, which was installed for one `toDataURL` call, so removing
// that library took the Node types with it and thirty-two `node:*` imports
// stopped type-checking at once. `@types/node` is a devDependency of this
// package now, and this line is what puts it in the program: automatic @types
// discovery only picks up `vite/client` here.
/// <reference types="node" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<object, object, unknown>
  export default component
}

interface ImportMetaEnv {
  /** API origin override. Dev-only unless VITE_VAULT_URL_ALLOW_PRODUCTION is set. */
  readonly VITE_VAULT_URL?: string
  /** Opts a production build into honouring VITE_VAULT_URL. Must be the string 'true'. */
  readonly VITE_VAULT_URL_ALLOW_PRODUCTION?: string
}
