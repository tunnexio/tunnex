import type { ReactNode } from "react";

/** Display-only tokenization; copying continues to use the original source. */
export function AICodeBlock({ source, language, showTitle = true }: { source: string; language: string; showTitle?: boolean }) {
  const files: Record<string, string> = { python: "example.py", shell: "request.sh", javascript: "example.mjs", typescript: "example.ts", go: "main.go", java: "Example.java", csharp: "Program.cs", php: "example.php", ruby: "example.rb", http: "request.http" };
  const tokens: ReactNode[] = [];
  const pattern = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|#[^\n]*|\b(?:from|import|as|if|else|True|False|None|export)\b|\b\d+(?:\.\d+)?\b|\b[A-Za-z_]\w*(?=\())/g;
  let offset = 0;
  for (const match of source.matchAll(pattern)) {
    const index = match.index!;
    if (index > offset) tokens.push(source.slice(offset, index));
    const value = match[0];
    const kind = value.startsWith("#") ? "comment" : /^["']/.test(value) ? "string" : /^\d/.test(value) ? "number" : /^(from|import|as|if|else|True|False|None|export)$/.test(value) ? "keyword" : "function";
    tokens.push(<span className={`ai-code-${kind}`} key={index}>{value}</span>);
    offset = index + value.length;
  }
  tokens.push(source.slice(offset));
  return <div className="ai-code-editor">{showTitle && <div className="ai-code-title"><span aria-hidden="true">{language.toUpperCase()}</span>{files[language] ?? "example.txt"}</div>}<pre tabIndex={0} aria-label={`${language} code example`}><code>{tokens}</code></pre></div>;
}
