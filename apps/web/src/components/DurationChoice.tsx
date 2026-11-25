import { Button } from "./ui";

// SA-UX-2 audit S10: common durations one click away, and the resulting end time in words.
const presets: [number, string][] = [[1, "1 hour"], [8, "8 hours"], [24, "1 day"], [168, "7 days"]];
export function DurationChoice({ hours, max = 168, onChange, disabled }: { hours: number; max?: number; onChange: (hours: number) => void; disabled?: boolean }) {
  const valid = Number.isFinite(hours) && hours >= 1 && hours <= max;
  return <div className="space-y-1">
    <div className="flex flex-wrap gap-2" role="group" aria-label="Common durations">{presets.filter(([value]) => value <= max).map(([value, label]) => <Button key={value} type="button" variant={hours === value ? undefined : "ghost"} aria-pressed={hours === value} disabled={disabled} onClick={() => onChange(value)}>{label}</Button>)}</div>
    <p className="text-xs text-ink-secondary">{valid ? `Access ends ${new Date(Date.now() + hours * 3600000).toLocaleString()}.` : `Choose between 1 hour and ${max / 24} days.`}</p>
  </div>;
}
