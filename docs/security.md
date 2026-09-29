# MAILTRACE 2.0 Security Guidelines & Principles

## Security Architecture Principles

1. **API Key & Secret Protection**:
   * API keys (VirusTotal, MaxMind, OpenAI, Gemini, JWT secrets) are NEVER embedded in frontend or extension source bundles.
   * All API key operations reside strictly within backend services configured via `.env`.

2. **Untrusted Input Handling**:
   * Email headers, HTML bodies, and extracted URLs are treated as high-risk untrusted inputs.
   * DOM rendering uses strict React JSX escaping; usage of `dangerouslySetInnerHTML`, `eval()`, or unsafe dynamic scripts is strictly forbidden.

3. **Execution Prevention & Isolation**:
   * Email attachments are NEVER automatically opened, rendered, or executed.
   * URLs extracted during IOC analysis are NEVER automatically visited or pre-fetched by client extensions.

4. **Dynamic & Configurable CORS**:
   * Backend CORS origins are restricted to explicitly configured values in `ALLOWED_CORS_ORIGINS`.

5. **Strict Typed Contracts**:
   * APIs strictly enforce typed Pydantic request/response validation on the backend and TypeScript interfaces on the frontend.
