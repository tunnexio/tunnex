import { aiOperationExample, aiOperationSpec } from "./aiOperationExample";
export type CodeExample = { label: string; language: string; source: string };

/** Every example uses the same VPN endpoint and the connected device's identity. */
export function aiLanguageExamples(base: string, model: string, mode: string): CodeExample[] {
  const op = aiOperationSpec(model, mode);
  const curl = aiOperationExample(base, model, mode);
  if (!op || !curl) return [];
  const result: CodeExample[] = [{ label: "cURL", language: "shell", source: curl }];
  const url = base + "/" + op.route, body = JSON.stringify(op.body), q = JSON.stringify;
  const headers = { "Content-Type": "application/json" };
  const js = `const response = await fetch(${q(url)}, {\n  method: "POST",\n  headers: ${JSON.stringify(headers, null, 2)},\n  body: ${q(body)},\n});\nif (!response.ok) throw new Error(await response.text());\nconsole.log(await response.json());`;
  result.push({ label: "Python", language: "python", source: `import json, urllib.request\n\nrequest = urllib.request.Request(\n    ${q(url)},\n    data=${q(body)}.encode(),\n    headers=${JSON.stringify(headers)},\n    method="POST",\n)\nwith urllib.request.urlopen(request) as response:\n    print(json.loads(response.read()))` });
  result.push({ label: "JavaScript", language: "javascript", source: js }, { label: "TypeScript", language: "typescript", source: js });
  result.push({ label: "Go", language: "go", source: `package main\n\nimport ("bytes"; "fmt"; "io"; "net/http")\n\nfunc main() {\n    req, err := http.NewRequest("POST", ${q(url)}, bytes.NewBufferString(${q(body)}))\n    if err != nil { panic(err) }\n    req.Header.Set("Content-Type", "application/json")\n    res, err := http.DefaultClient.Do(req)\n    if err != nil { panic(err) }\n    defer res.Body.Close()\n    data, err := io.ReadAll(res.Body)\n    if err != nil { panic(err) }\n    if res.StatusCode >= 300 { panic(string(data)) }\n    fmt.Println(string(data))\n}` });
  result.push({ label: "Java", language: "java", source: `import java.net.URI;\nimport java.net.http.*;\n\nclass Example {\n  public static void main(String[] args) throws Exception {\n    var request = HttpRequest.newBuilder(URI.create(${q(url)}))\n    .header("Content-Type", "application/json")\n    .POST(HttpRequest.BodyPublishers.ofString(${q(body)})).build();\n    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofByteArray());\n    if (response.statusCode() >= 300) throw new RuntimeException(new String(response.body()));\n    System.out.println(new String(response.body()));\n  }\n}` });
  result.push({ label: "C#", language: "csharp", source: `using System;\nusing System.Net.Http;\nusing System.Text;\n\nusing var client = new HttpClient();\nusing var response = await client.PostAsync(${q(url)}, new StringContent(${q(body)}, Encoding.UTF8, "application/json"));\nresponse.EnsureSuccessStatusCode();\nConsole.WriteLine(await response.Content.ReadAsStringAsync());` });
  const phpQuote = (v: string) => "'" + v.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
  result.push({ label: "PHP", language: "php", source: `<?php\n$ch = curl_init(${phpQuote(url)});\ncurl_setopt_array($ch, [\n  CURLOPT_POST => true,\n  CURLOPT_RETURNTRANSFER => true,\n  CURLOPT_HTTPHEADER => ["Content-Type: application/json"],\n  CURLOPT_POSTFIELDS => ${phpQuote(body)},\n]);\n$result = curl_exec($ch);\nif ($result === false || curl_getinfo($ch, CURLINFO_HTTP_CODE) >= 300) { throw new Exception(curl_error($ch) ?: $result); }\necho $result;\ncurl_close($ch);` });
  result.push({ label: "Ruby", language: "ruby", source: `require "net/http"\nrequire "uri"\n\nuri = URI(${q(url)})\nrequest = Net::HTTP::Post.new(uri)\nrequest["Content-Type"] = "application/json"\nrequest.body = ${phpQuote(body)}\nresponse = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }\nraise response.body unless response.is_a?(Net::HTTPSuccess)\nputs response.body` });
  const parsed = new URL(url);
  result.push({ label: "HTTP / REST", language: "http", source: `POST ${parsed.pathname} HTTP/1.1\nHost: ${parsed.host}\nContent-Type: application/json\n\n${JSON.stringify(op.body, null, 2)}` });
  return result;
}
