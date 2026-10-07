function base64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read this screenshot."));
    reader.onload = () => {
      const encoded = typeof reader.result === "string" ? reader.result.split(",")[1] : "";
      if (encoded) resolve(encoded); else reject(new Error("Could not read this screenshot."));
    };
    reader.readAsDataURL(blob);
  });
}
function jpeg(canvas: HTMLCanvasElement, quality: number): Promise<Blob> {
  return new Promise((resolve, reject) => canvas.toBlob(blob => blob ? resolve(blob) : reject(new Error("Could not prepare this screenshot.")), "image/jpeg", quality));
}

// Keep the original file local. The server receives only the bounded review
// image and independently decodes, validates and strips image metadata.
export async function prepareBeamScreenshot(file: File): Promise<string> {
  if (!["image/png", "image/jpeg"].includes(file.type) || !file.size || file.size > 10 * 1024 * 1024) throw new Error("Choose a PNG or JPEG screenshot no larger than 10 MB.");
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    await new Promise<void>((resolve, reject) => { image.onload = () => resolve(); image.onerror = () => reject(new Error("This screenshot could not be opened. Choose a PNG or JPEG image.")); image.src = url; });
    if (!image.naturalWidth || !image.naturalHeight || image.naturalWidth * image.naturalHeight > 40000000) throw new Error("Crop this screenshot to a smaller image before attaching it.");
    const canvas = document.createElement("canvas"), context = canvas.getContext("2d");
    if (!context) throw new Error("Your browser could not prepare the screenshot. Try another browser.");
    const scale = Math.min(1, 1600 / Math.max(image.naturalWidth, image.naturalHeight));
    canvas.width = Math.max(1, Math.floor(image.naturalWidth * scale)); canvas.height = Math.max(1, Math.floor(image.naturalHeight * scale));
    context.fillStyle = "#ffffff"; context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    for (const quality of [0.9, 0.75, 0.6, 0.45]) {
      const result = await jpeg(canvas, quality);
      if (result.size <= 256 * 1024) return await base64(result);
    }
    throw new Error("This screenshot still exceeds the review limit. Crop it to the area you want to discuss.");
  } finally { URL.revokeObjectURL(url); }
}
