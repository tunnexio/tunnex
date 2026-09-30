// The URL remembers navigation only. It never certifies that setup succeeded.
export function setupStep(value: string | null): number {
  return value && /^[1-4]$/.test(value) ? Number(value) : 1;
}

export function setupReturnPath(purpose: string, step: string | null): string {
  const task = ["vpn", "networks", "kubernetes"].includes(purpose) ? purpose : "vpn";
  return `/setup?purpose=${task}&step=${setupStep(step)}`;
}
