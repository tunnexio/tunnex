import { describe, expect, it, afterEach } from "vitest";
import { render, screen, within, cleanup } from "@testing-library/react";
import {
  Badge,
  DataTable,
  EmptyState,
  Field,
  Input,
  List,
  ListItem,
  Loading,
  Modal,
  Panel,
} from "../src/components/ui";

// S14.3 SLICE A — THE PRIMITIVE CENSUS.
//
// ⛔ A PRIMITIVE THAT IS NOT QUERYABLE BY ROLE IS NOT DONE, and that is a mechanism here rather than a review
// note. Query rule 1 binds the whole tier to role + accessible name; a primitive that renders an anonymous
// <div> forces every screen built from it back onto text matching — which is what the previous absence of a
// <table> did to all eight wiring slices.
//
// Each case names the ROLE the primitive must expose and the NAME it must carry. Removing an accessible name
// from any of them turns its assertion red; that is proven by mutation, not asserted here.

afterEach(cleanup); // no globals/setup file, so auto-cleanup never registers (docs/laws.md)

describe("every structural primitive is queryable by ROLE and NAME", () => {
  it("Panel is a named region — an unnamed section cannot be told from any other section", () => {
    render(<Panel title="Rules">body</Panel>);
    expect(screen.getByRole("region", { name: "Rules" })).toBeTruthy();
  });

  it("List is a list with a name", () => {
    render(
      <List label="Gateways">
        <ListItem>one</ListItem>
      </List>,
    );
    const list = screen.getByRole("list", { name: "Gateways" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
  });

  it("Loading is ANNOUNCED, not merely drawn — a spinner nothing announces is invisible to a screen reader", () => {
    render(<Loading />);
    expect(screen.getByRole("status")).toBeTruthy();
  });

  it("Field associates its <label> with its control, so the control's accessible NAME is the label", () => {
    render(
      <Field label="Device name">
        <Input />
      </Field>,
    );
    // getByLabelText resolves through the for/id association. If the association broke, the control would
    // still render and still look correct — and would have no name at all.
    expect(screen.getByLabelText("Device name")).toBeTruthy();
  });

  it("Modal is a named dialog", () => {
    render(
      <Modal title="Revoke device" onDismiss={() => {}} actions={null}>
        body
      </Modal>,
    );
    expect(screen.getByRole("dialog", { name: "Revoke device" })).toBeTruthy();
  });

  it("EmptyState says what is empty — and is DISTINCT from a failure, which must never reach it", () => {
    render(<EmptyState>No devices yet.</EmptyState>);
    expect(screen.getByText("No devices yet.")).toBeTruthy();
  });

  it("Badge carries its status as TEXT — colour is an accelerant, never the carrier", () => {
    // Three failures with one cause if this regresses: unreadable to a colour-blind user, invisible to a
    // screen reader, unqueryable by the tier. Which is why `children` is required rather than optional.
    render(<Badge tone="danger">revoked</Badge>);
    expect(screen.getByText("revoked")).toBeTruthy();
  });
});

describe("DataTable — the primitive the app did not have", () => {
  const rows = [
    { id: "a", name: "alpha", ip: "10.0.0.1" },
    { id: "b", name: "beta", ip: "10.0.0.2" },
  ];
  const columns = [
    { key: "name", header: "Name", cell: (r: (typeof rows)[number]) => r.name },
    { key: "ip", header: "Address", cell: (r: (typeof rows)[number]) => r.ip },
  ];
  const table = (
    over: Partial<Parameters<typeof DataTable<(typeof rows)[number]>>[0]> = {},
  ) => (
    <DataTable
      caption="Things"
      columns={columns}
      rows={rows}
      rowKey={(r) => r.id}
      empty="None yet."
      failed={false}
      {...over}
    />
  );

  it("is a table with an accessible NAME — two unnamed tables on a screen are indistinguishable", () => {
    render(table());
    expect(screen.getByRole("table", { name: "Things" })).toBeTruthy();
  });

  it("exposes column headers, so a cell's value can be identified", () => {
    render(table());
    expect(screen.getByRole("columnheader", { name: "Name" })).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Address" })).toBeTruthy();
  });

  it("exposes rows and cells — header row plus one row per record", () => {
    render(table());
    const t = screen.getByRole("table", { name: "Things" });
    expect(within(t).getAllByRole("row")).toHaveLength(3); // 1 header + 2 records
    const alpha = within(t)
      .getAllByRole("row")
      .find((r) => within(r).queryByText("alpha"))!;
    expect(within(alpha).getByText("10.0.0.1")).toBeTruthy();
  });

  it("zero rows renders the EMPTY message", () => {
    render(table({ rows: [] }));
    expect(screen.getByText("None yet.")).toBeTruthy();
  });

  it("⛔ A FAILED LOAD RENDERS NEITHER THE TABLE NOR THE EMPTY MESSAGE", () => {
    // The defect this slice introduced and the tier caught. An empty array means two different things —
    // "there are none" and "we never found out" — and rendering the second as the first is the
    // reassuring-empty defect. On a roster it is a claim about who can administer the org, made by a screen
    // that never successfully read anything.
    render(table({ rows: [], failed: true }));
    expect(screen.queryByText("None yet.")).toBeNull();
    expect(screen.queryByRole("table", { name: "Things" })).toBeNull();
  });

  it("a failed load with rows ALREADY IN HAND still renders nothing — stale rows are not a successful read", () => {
    // The subtler half. If a refresh fails, the previous page's rows are still in state; showing them under a
    // failed load presents old data as current, which is the same lie one step quieter.
    render(table({ failed: true }));
    expect(screen.queryByRole("table", { name: "Things" })).toBeNull();
  });
});
