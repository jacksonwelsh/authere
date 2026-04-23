// Minimal ambient types for the qrcode package — only the `toString` shape we use.
// Full types live in @types/qrcode; this keeps us dep-free for a single call site.
declare module 'qrcode' {
  interface QRCodeToStringOptions {
    type?: 'svg' | 'utf8' | 'terminal';
    errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
    margin?: number;
    width?: number;
    color?: { dark?: string; light?: string };
  }
  function toString(text: string, options?: QRCodeToStringOptions): Promise<string>;
  const _default: { toString: typeof toString };
  export { toString };
  export default _default;
}
