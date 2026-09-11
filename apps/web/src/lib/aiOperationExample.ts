const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";

/** Examples follow the gateway contract, not provider-specific SDK extensions. */
export function aiOperationExample(base: string, model: string, mode: string): string | null {
  const operations: Record<string, { route: string; body: Record<string, unknown> }> = {
    completion: { route: "completions", body: { model, prompt: "Hello", max_tokens: 256 } },
    embedding: { route: "embeddings", body: { model, input: "Text to embed" } },
    audio_speech: { route: "audio/speech", body: { model, input: "Hello", voice: "REPLACE_WITH_SUPPORTED_VOICE", response_format: "mp3" } },
    image_generation: { route: "images/generations", body: { model, prompt: "A quiet mountain lake", n: 1 } },
    video_generation: { route: "videos", body: { model, prompt: "A quiet mountain lake", seconds: "4" } },
    rerank: { route: "rerank", body: { model, query: "What is Tunnex?", documents: ["Tunnex connects users and applications.", "A mountain lake."], top_n: 1 } },
  };
  const auth = '  -H "Authorization: Bearer ${TUNNEX_API_KEY:?Set a Tunnex credential first}"';
  if (mode === "audio_transcription") return [
    `curl --fail-with-body ${quote(base + "/audio/transcriptions")} \\`, auth + " \\",
    `  --form-string ${quote("model=" + model)} \\`, "  -F 'file=@audio.wav'",
  ].join("\n");
  const operation = operations[mode];
  if (!operation) return null;
  return [
    ...(mode === "video_generation" ? ['# Keep this key for retries; unset it before a different video job.', ': "${TUNNEX_VIDEO_IDEMPOTENCY_KEY:=$(uuidgen)}"'] : []),
    `curl --fail-with-body ${quote(base + "/" + operation.route)} \\`, auth + " \\",
    ...(mode === "video_generation" ? ['  -H "Idempotency-Key: ${TUNNEX_VIDEO_IDEMPOTENCY_KEY}" \\'] : []),
    "  -H 'Content-Type: application/json' \\",
    `  --data-raw ${quote(JSON.stringify(operation.body))}${mode === "audio_speech" ? " \\" : ""}`,
    ...(mode === "audio_speech" ? ["  --output speech.mp3"] : []),
  ].join("\n");
}
