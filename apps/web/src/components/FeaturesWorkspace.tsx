import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button, Input } from "./ui";
import "../features-workspace.css";

export type FeatureCategory = "Network" | "Access" | "AI" | "Kubernetes" | "Observe";
export type FeatureEntry = {
  id: string;
  name: string;
  category: FeatureCategory;
  keywords?: string;
  control: ReactNode;
};

/** Feature controllers stay mounted while filtering so in-flight outcomes and drafts remain scoped. */
export function FeaturesWorkspace({ entries }: { entries: FeatureEntry[] }) {
  const requested = new URLSearchParams(window.location.search).get("feature");
  const destination = entries.find(entry => entry.id === requested);
  const [category, setCategory] = useState<FeatureCategory | "All">(() => destination?.category ?? "All");
  const [query, setQuery] = useState("");
  const target = useRef<HTMLElement | null>(null);
  const focusedRequest = useRef<string | null>(null);
  const categories = ["All", ...Array.from(new Set(entries.map(entry => entry.category)))] as const;
  const search = query.trim().toLowerCase();
  const matches = (entry: FeatureEntry) => (category === "All" || entry.category === category)
    && `${entry.name} ${entry.category} ${entry.keywords ?? ""}`.toLowerCase().includes(search);
  const count = entries.filter(matches).length;

  useEffect(() => {
    if (!destination) return;
    setCategory(destination.category); setQuery("");
  }, [requested, destination?.category]);
  useEffect(() => {
    if (destination && category === destination.category && !query && focusedRequest.current !== requested) {
      focusedRequest.current = requested;
      target.current?.focus({ preventScroll: true });
      target.current?.scrollIntoView?.({ block: "nearest" });
    }
  }, [destination?.id, category, query]);

  return <div className="features-workspace">
    <div className="features-toolbar">
      <Input type="search" aria-label="Search features" placeholder="Find a feature…" value={query} onChange={event => setQuery(event.target.value)} />
      <span className="features-count">{count} {count === 1 ? "feature" : "features"}</span>
    </div>
    <div className="features-categories" role="group" aria-label="Feature categories">
      {categories.map(value => <button key={value} type="button" aria-pressed={category === value} onClick={() => setCategory(value)}>{value === "All" ? "All features" : value}</button>)}
    </div>
    <div className="features-list" aria-label="Organization features">
      {entries.map(entry => <section key={entry.id} id={`feature-${entry.id}`} aria-label={entry.name}
        hidden={!matches(entry)} tabIndex={-1} ref={entry.id === requested ? target : undefined}
        className={`features-entry${entry.id === requested ? " is-requested" : ""}`}>
        {entry.control}
      </section>)}
      {!count && <div className="features-empty"><h3>No matching features</h3><p>Try another name or category.</p><Button variant="ghost" onClick={() => { setQuery(""); setCategory("All"); }}>Clear filters</Button></div>}
    </div>
  </div>;
}
