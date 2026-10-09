import { useId, type ReactNode, type Ref } from "react";
import "../resource-summary.css";

type ResourceSummaryProps = {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  headingLevel?: 2 | 3 | 4;
  headingId?: string;
  headingRef?: Ref<HTMLHeadingElement>;
  className?: string;
};

/** A saved resource's facts, using the same hierarchy across detail screens. */
export function ResourceSummary({ title, children, actions, description, footer, headingLevel = 3, headingId, headingRef, className = "" }: ResourceSummaryProps) {
  const generatedId = useId();
  const titleId = headingId ?? `resource-summary-${generatedId}`;
  const Heading = `h${headingLevel}` as "h2" | "h3" | "h4";
  return <section className={`tnx-resource-summary ${className}`.trim()} aria-labelledby={titleId}>
    <header className="tnx-resource-summary-heading">
      <div><Heading id={titleId} ref={headingRef} tabIndex={headingRef ? -1 : undefined}>{title}</Heading>{description && <p>{description}</p>}</div>
      {actions && <div className="tnx-resource-summary-actions">{actions}</div>}
    </header>
    <div className="tnx-resource-summary-content">{children}</div>
    {footer && <footer className="tnx-resource-summary-footer">{footer}</footer>}
  </section>;
}
