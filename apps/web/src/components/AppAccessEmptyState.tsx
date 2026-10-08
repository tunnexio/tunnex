import type { ReactNode } from "react";
import { Icon, type IconName } from "./Icon";

export default function AppAccessEmptyState({ title, description, action, icon = "app-grid" }: { title: string; description?: ReactNode; action?: ReactNode; icon?: IconName | null }) {
  return <div className="aa-empty-state">
    {icon && <span className="aa-empty-state-icon" aria-hidden="true"><Icon name={icon} size={24} /></span>}
    <div className="aa-empty-state-copy" role="status"><h3>{title}</h3>{description && <p>{description}</p>}</div>
    {action && <div className="aa-empty-state-actions">{action}</div>}
  </div>;
}
