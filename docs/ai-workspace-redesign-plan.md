# AI workspace redesign

Reference: LiteLLM's model-management organization, with Tunnex's Access Policies table and dialog interactions. Keep Tunnex's dark theme and existing API contracts.

## Interaction rules

- One page title, one inventory toolbar, one primary create action.
- Searchable inventories are the default view. Create, edit, assign and test operations stay in dialogs, retaining selection and filters.
- Use short names in rows. Exact identifiers remain available in details and copy controls.
- Keep supporting explanations in keyboard-accessible, dismissible tooltips. Keep errors, required-field validation and consequential confirmation text visible.
- Use distinct AI Gateway, Agent and MCP icons with consistent size and stroke.
- No em dashes in product copy.

## Implementation sequence

1. Shared help tooltip and compact workspace styling; distinct navigation icons.
2. Models and credentials: remove duplicate headings, compact rows, open provider forms in dialogs, keep model access assignment in context.
3. User access: searchable grant inventory with a Grant access dialog. Keep workload inventory and existing dialogs.
4. Agent model access: show saved group policies and agent assignments first; open their existing editors on demand.
5. MCP: show profile inventory first; selected profile, assignments and tool discovery in a detail dialog. Preserve impact previews and permission checks.
6. Agent inventory, policy templates, settings and personal model tools: concise copy, optional help, consistent details and actions.
7. Verify type checking, affected interaction tests, full web suite, keyboard dialog/tooltip behavior and desktop/narrow browser layouts. Check mutation flows without changing authorization or inventing successful runtime states.

## Acceptance

A user can identify configured items immediately, add or edit an item without losing the inventory context, and find explanations on demand. Existing permissions, provider secrets handling, revision checks, impact previews, and error reporting continue to work. Existing local changes from the punctuation cleanup are retained.

## First implementation delivered

Implemented compact model rows and distinct navigation icons; provider create/edit/delete dialogs; contextual model grants; searchable user-grant inventory; saved team-policy and agent-assignment inventories with editors in dialogs; MCP profile details in a dialog; optional help across provider forms, agent inventory, policy templates, settings and My models. Connection instructions in My models are opened on demand.

Validation: TypeScript check passed; 128 web test files and 1,528 tests passed; whitespace check passed. Local browser checks covered model creation, contextual grants, MCP details and agent policy editing with seeded data. Desktop model inventory was visually reviewed. Narrow-screen browser validation remains a follow-up; tables retain horizontal scrolling on small screens.
