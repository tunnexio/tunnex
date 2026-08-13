import { afterEach, describe, expect, it } from "vitest";
import {
  cleanup,
  render,
  screen,
  fireEvent,
  within,
} from "@testing-library/react";
import { DataTable, pageWindow } from "../src/components/ui";

afterEach(cleanup);

type Row = { id: string; name: string; owner: string; state: string };

const ROWS: Row[] = [
  { id: "1", name: "zebra", owner: "ana@ex.com", state: "revoked" },
  { id: "2", name: "alpha", owner: "bo@ex.com", state: "active" },
  { id: "3", name: "mango", owner: "ana@ex.com", state: "active" },
];

function table(rows: Row[] = ROWS, failed = false) {
  return render(
    <DataTable<Row>
      caption="Widgets"
      rows={rows}
      failed={failed}
      rowKey={(r) => r.id}
      empty="No widgets exist."
      columns={[
        {
          key: "name",
          header: "Name",
          // The owner is searchable although this column never displays it.
          sortValue: (r) => `${r.name} ${r.owner}`,
          cell: (r) => <span>{r.name}</span>,
        },
        // ⛔ The state's TEXT lives in sortValue because the cell renders it as a styled element.
        {
          key: "state",
          header: "State",
          sortValue: (r) => r.state,
          cell: (r) => <em>{r.state}</em>,
        },
        { key: "plain", header: "Plain", cell: () => <span>x</span> },
      ]}
    />,
  );
}

const bodyNames = () =>
  screen
    .getAllByRole("row")
    .slice(1)
    .map((r) => within(r).getAllByRole("cell")[0].textContent);

describe("DataTable — scannability", () => {
  it("⛔ A SORTABLE HEADER'S NAME IS STILL ITS HEADER", () => {
    // The sort indicator is an SVG precisely so it contributes no text. A character glyph would make this
    // column's name "Name↕" and silently break every query and test that names a column — which is how it
    // was caught: three existing suites went red at once.
    table();
    expect(screen.getByRole("columnheader", { name: "Name" })).toBeTruthy();
    const headers = screen
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual(["Name", "State", "Plain"]);
  });

  it("sorts ascending, then descending, and announces which via aria-sort", () => {
    table();
    const btn = within(
      screen.getByRole("columnheader", { name: "Name" }),
    ).getByRole("button");
    fireEvent.click(btn);
    expect(bodyNames()).toEqual(["alpha", "mango", "zebra"]);
    expect(
      screen
        .getByRole("columnheader", { name: "Name" })
        .getAttribute("aria-sort"),
    ).toBe("ascending");
    fireEvent.click(btn);
    expect(bodyNames()).toEqual(["zebra", "mango", "alpha"]);
    expect(
      screen
        .getByRole("columnheader", { name: "Name" })
        .getAttribute("aria-sort"),
    ).toBe("descending");
  });

  it("⚠ A COLUMN WITHOUT sortValue IS NOT SORTABLE — and is still a real header", () => {
    // Without this, "every header is a button" would pass the test above while making an unsortable column
    // click to nothing, which is a control that lies about what it does.
    table();
    const plain = screen.getByRole("columnheader", { name: "Plain" });
    expect(within(plain).queryByRole("button")).toBeNull();
  });

  it("filters on sortValue, INCLUDING text the cell never shows", () => {
    table();
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Filter Widgets" }),
      {
        target: { value: "ana@ex.com" },
      },
    );
    // Two rows share that owner, and neither cell renders it.
    expect(bodyNames()).toEqual(["zebra", "mango"]);
    // ⚠ ONE PAGE: the range is noise ("1–2 of 2"), but the narrowing is not. The count says what was
    // filtered FROM; the row positions are only worth printing when there are pages to move between.
    expect(screen.getByText("2 of 3")).toBeTruthy();
  });

  it("⭐ finds a row by a state its cell renders as a styled element, not as plain text", () => {
    table();
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Filter Widgets" }),
      {
        target: { value: "revoked" },
      },
    );
    expect(bodyNames()).toEqual(["zebra"]);
  });

  it("⛔ A FILTER THAT MATCHES NOTHING IS NOT THE SAME CLAIM AS HAVING NOTHING", () => {
    // THE WHOLE POINT. `empty` says none exist; a filter miss says none match. Rendering the second as the
    // first tells an operator a resource does not exist when it is one keystroke away — a new way to
    // manufacture the reassuring empty on a component whose `failed` prop exists because of that class.
    table();
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Filter Widgets" }),
      {
        target: { value: "nothing-matches-this" },
      },
    );
    expect(screen.queryByText("No widgets exist.")).toBeNull();
    expect(screen.getByText(/No widgets match/)).toBeTruthy();
    // ⚠ And the way back is offered, with the true total — a dead end would leave the operator believing it.
    expect(screen.getByText(/see all 3/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filter" }));
    expect(bodyNames()).toHaveLength(3);
  });

  it("genuinely zero rows renders the empty copy, and a FAILED load renders nothing at all", () => {
    // The three states, asserted apart. A failed load must not borrow either emptiness — the page owns retry.
    const { unmount } = table([]);
    expect(screen.getByText("No widgets exist.")).toBeTruthy();
    unmount();
    table(ROWS, true);
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText("No widgets exist.")).toBeNull();
  });

  it("⚠ SORTING DOES NOT MUTATE THE CALLER'S ARRAY", () => {
    // `rows` is the page's state. Sorting in place would reorder it under React and make the next render
    // disagree with the data the page thinks it holds.
    const rows = [...ROWS];
    render(
      <DataTable<Row>
        caption="Copy check"
        rows={rows}
        failed={false}
        rowKey={(r) => r.id}
        empty="none"
        defaultSortKey="name"
        columns={[
          {
            key: "name",
            header: "Name",
            sortValue: (r) => r.name,
            cell: (r) => <span>{r.name}</span>,
          },
        ]}
      />,
    );
    expect(rows.map((r) => r.name)).toEqual(["zebra", "alpha", "mango"]);
  });
});

/**
 * ⛔ PAGINATION IS THREE MORE WAYS TO RENDER AN EMPTY TABLE OVER A FULL DATA SET, and every one of them
 * arrives by arithmetic rather than by a failed load — which is what makes them easy to ship. Narrowing
 * while deep in the list, resizing the page, and rows shrinking underneath all point the page index past
 * the end of the array.
 */
describe("DataTable — pagination", () => {
  const many = (n: number): Row[] =>
    Array.from({ length: n }, (_, i) => ({
      id: String(i),
      name: `row-${String(i).padStart(3, "0")}`,
      owner: i % 2 ? "ana@ex.com" : "bo@ex.com",
      state: "active",
    }));

  function paged(rows: Row[], pageSize?: number) {
    return render(
      <DataTable<Row>
        caption="Widgets"
        rows={rows}
        failed={false}
        rowKey={(r) => r.id}
        empty="No widgets exist."
        {...(pageSize === undefined ? {} : { pageSize })}
        columns={[
          {
            key: "name",
            header: "Name",
            sortValue: (r) => `${r.name} ${r.owner}`,
            cell: (r) => <span>{r.name}</span>,
          },
        ]}
      />,
    );
  }

  it("shows one page, not everything, and says which page it is showing", () => {
    paged(many(60));
    expect(screen.getAllByRole("row")).toHaveLength(26); // 25 + the header
    expect(screen.getByText("1–25 of 60")).toBeTruthy();
    expect(
      screen
        .getByRole("button", { name: "Page 1" })
        .getAttribute("aria-current"),
    ).toBe("page");
  });

  it("pages forward and back, and the boundary buttons are disabled at the boundaries", () => {
    paged(many(60));
    expect(
      screen
        .getByRole("button", { name: "Previous page" })
        .hasAttribute("disabled"),
    ).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(bodyNames()[0]).toBe("row-025");
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(
      screen
        .getByRole("button", { name: "Page 3" })
        .getAttribute("aria-current"),
    ).toBe("page");
    // ⚠ The last page is SHORT, and that is not an empty page — 60 rows over 25 leaves 10.
    expect(screen.getAllByRole("row")).toHaveLength(11);
    expect(
      screen
        .getByRole("button", { name: "Next page" })
        .hasAttribute("disabled"),
    ).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    expect(
      screen
        .getByRole("button", { name: "Page 2" })
        .getAttribute("aria-current"),
    ).toBe("page");
  });

  it("⭐ FILTERING FROM A DEEP PAGE RETURNS TO PAGE ONE — the operator's own search must not read as empty", () => {
    // Without the reset: page 3 of a 60-row list, filter down to 30 matches, and slice(50, 75) is EMPTY.
    // A full result set renders as nothing, and the thing that produced it was the search itself.
    paged(many(60));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(
      screen
        .getByRole("button", { name: "Page 3" })
        .getAttribute("aria-current"),
    ).toBe("page");
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Filter Widgets" }),
      {
        target: { value: "ana@ex.com" },
      },
    );
    expect(bodyNames().length).toBeGreaterThan(0);
    expect(screen.getByText("1–25 of 30 (filtered from 60)")).toBeTruthy();
  });

  it("⭐ ROWS SHRINKING UNDER A DEEP PAGE CLAMPS INSTEAD OF RENDERING NOTHING", () => {
    // A revoke, a refetch, a sweep — the page index that was valid a moment ago now points past the end.
    // Clamped at RENDER, so there is no frame in which the stale index is used.
    const { rerender } = paged(many(60));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(
      screen
        .getByRole("button", { name: "Page 3" })
        .getAttribute("aria-current"),
    ).toBe("page");
    rerender(
      <DataTable<Row>
        caption="Widgets"
        rows={many(30)}
        failed={false}
        rowKey={(r) => r.id}
        empty="No widgets exist."
        columns={[
          {
            key: "name",
            header: "Name",
            sortValue: (r) => r.name,
            cell: (r) => <span>{r.name}</span>,
          },
        ]}
      />,
    );
    expect(bodyNames().length).toBeGreaterThan(0);
    expect(
      screen
        .getByRole("button", { name: "Page 2" })
        .getAttribute("aria-current"),
    ).toBe("page");
  });

  it("⚠ NO PAGER WHEN EVERYTHING ALREADY FITS — a control that can only no-op implies there is more", () => {
    paged(many(5));
    expect(screen.queryByRole("button", { name: "Next page" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Page 2" })).toBeNull();
    expect(screen.getAllByRole("row")).toHaveLength(6);
  });

  it("⛔ pageSize={0} DISABLES PAGING ENTIRELY — for surfaces that already page server-side", () => {
    // AuditLog and AccessEvents fetch behind a keyset cursor. A second pager there would append rows the
    // operator cannot see and report a count describing neither the fetch nor the view.
    paged(many(60), 0);
    expect(screen.getAllByRole("row")).toHaveLength(61);
    expect(screen.queryByRole("button", { name: "Next page" })).toBeNull();
  });

  it("changing rows-per-page returns to the first page", () => {
    paged(many(60));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(bodyNames()[0]).toBe("row-025");
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), {
      target: { value: "50" },
    });
    expect(bodyNames()[0]).toBe("row-000");
    expect(screen.getByText("1–50 of 60")).toBeTruthy();
  });
});

/**
 * ⛔ SELECTION IS THE MOST DANGEROUS THING A TABLE OFFERS, because the operator's next click is a BULK action
 * and the set it applies to is whatever this component decided. Both ambiguities are resolved conservatively
 * and pinned here.
 */
describe("DataTable — selection", () => {
  const many = (n: number): Row[] =>
    Array.from({ length: n }, (_, i) => ({
      id: String(i),
      name: `row-${String(i).padStart(3, "0")}`,
      owner: i % 2 ? "ana@ex.com" : "bo@ex.com",
      state: "active",
    }));

  function sel(rows: Row[], pageSize = 25) {
    const seen: string[][] = [];
    render(
      <DataTable<Row>
        caption="Widgets"
        rows={rows}
        failed={false}
        rowKey={(r) => r.id}
        empty="No widgets exist."
        selectable
        pageSize={pageSize}
        onSelectionChange={(k) => seen.push(k)}
        bulkActions={(keys) => (
          <button type="button">Revoke {keys.length}</button>
        )}
        columns={[
          {
            key: "name",
            header: "Name",
            sortValue: (r) => `${r.name} ${r.owner}`,
            cell: (r) => <span>{r.name}</span>,
          },
        ]}
      />,
    );
    return seen;
  }

  it("⭐ THE HEADER CHECKBOX SELECTS THE PAGE, NEVER THE WHOLE RESULT SET", () => {
    // "Select all" meaning 60 invisible rows is how a bulk revoke becomes an outage: the operator sees 25
    // rows and reasons about 25. The label says which it is, so the claim is checkable rather than assumed.
    sel(many(60));
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select all 25 on this page" }),
    );
    // Scoped to the selection bar: "25" also appears as a rows-per-page option, and a document-wide match
    // would pass on the wrong element entirely.
    const bar = screen.getByText("selected", { exact: false }).closest("span")!;
    expect(bar.textContent).toContain("25 selected");
    expect(bar.textContent).not.toContain("60 selected");
  });

  it("⚠ …AND SELECTING EVERYTHING IS STILL POSSIBLE, BY A CONTROL THAT SAYS THE NUMBER", () => {
    // Conservative must not mean impossible. The escape hatch exists; it just refuses to be the default,
    // and it states the count in its own label rather than in a tooltip.
    sel(many(60));
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select all 25 on this page" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Select all 60 matching" }),
    );
    expect(
      screen.getByText("selected", { exact: false }).closest("span")!
        .textContent,
    ).toContain("60 selected");
  });

  it("⭐ A SELECTION HIDDEN BY A FILTER IS COUNTED AND SAID OUT LOUD", () => {
    // Selection survives filtering on purpose — silently dropping rows would make the APPLIED set differ
    // from the COUNTED set, which is worse than a warning. So the warning has to exist.
    sel(many(60));
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select all 25 on this page" }),
    );
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Filter Widgets" }),
      {
        target: { value: "ana@ex.com" },
      },
    );
    expect(
      screen.getByText(/not visible under the current filter/),
    ).toBeTruthy();
  });

  it("reports the selection to the caller, and Clear empties it", () => {
    const seen = sel(many(10), 25);
    fireEvent.click(screen.getByRole("checkbox", { name: /^Select row-000/ }));
    expect(seen[seen.length - 1]).toEqual(["0"]);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(seen[seen.length - 1]).toEqual([]);
  });

  it("⚠ THE BAR IS PRESENT AT ZERO — a footer that appears on first click moves the layout under the cursor", () => {
    sel(many(10));
    expect(
      screen.getByText("Select one or more rows to act on them"),
    ).toBeTruthy();
    // And the bulk action is ABSENT until there is something to act on: an enabled verb over an empty
    // selection is a control that can only fail.
    expect(screen.queryByRole("button", { name: /^Revoke/ })).toBeNull();
    fireEvent.click(screen.getByRole("checkbox", { name: /^Select row-000/ }));
    expect(screen.getByRole("button", { name: "Revoke 1" })).toBeTruthy();
  });

  it("⛔ THE CHECKBOX IS NAMED BY THE ROW, NOT BY ITS DATABASE ID", () => {
    // Without the derivation a screen-reader user hears "select 019fcda7-7718-77e3" — an unidentifiable
    // control on the one interaction whose next step is a bulk action.
    sel(many(3));
    const box = screen.getAllByRole("checkbox")[1];
    expect(box.getAttribute("aria-label")).toContain("row-000");
    expect(box.getAttribute("aria-label")).not.toMatch(/Select \d+$/);
  });

  it("⚠ NO CHECKBOXES WHEN THE TABLE IS NOT SELECTABLE", () => {
    render(
      <DataTable<Row>
        caption="Widgets"
        rows={many(3)}
        failed={false}
        rowKey={(r) => r.id}
        empty="none"
        columns={[
          { key: "name", header: "Name", cell: (r) => <span>{r.name}</span> },
        ]}
      />,
    );
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
  });
});

describe("pageWindow — always first, last, and the neighbourhood", () => {
  it("lists every page when they fit", () => {
    expect(pageWindow(0, 3)).toEqual([0, 1, 2, 3]);
  });

  it("⛔ KEEPS THE LAST PAGE VISIBLE — eliding it hides how much there is", () => {
    // "How much is there" is the question a pager exists to answer, so the far end is never the thing cut.
    const w = pageWindow(0, 20);
    expect(w[0]).toBe(0);
    expect(w[w.length - 1]).toBe(20);
    expect(w).toContain(null);
  });

  it("keeps the current page and its neighbours", () => {
    const w = pageWindow(10, 20);
    expect(w).toContain(9);
    expect(w).toContain(10);
    expect(w).toContain(11);
  });
});

/**
 * ⛔ ONE BAR INSTEAD OF THREE BUTTONS PER ROW — and the thing that makes it safe is `unavailable`.
 *
 * Moving verbs off the rows is a layout win. The RISK it introduces is that a selection is almost never
 * uniform: five rules where one is GitOps-managed, three devices where one is already revoked. A bulk verb
 * then has two bad options — silently skip the ineligible rows, or silently attempt them — and both leave
 * the operator believing they did something they did not do.
 *
 * > **THE SET AN ACTION APPLIES TO MUST BE STATED BEFORE IT RUNS, NOT DISCOVERED AFTERWARDS.**
 */
describe("DataTable — row actions in one bar", () => {
  const ROWS3: Row[] = [
    { id: "1", name: "alpha", owner: "a@x.com", state: "active" },
    { id: "2", name: "bravo", owner: "b@x.com", state: "locked" },
    { id: "3", name: "cocoa", owner: "c@x.com", state: "active" },
  ];

  let ran: string[][] = [];
  function acts(rows: Row[] = ROWS3) {
    ran = [];
    render(
      <DataTable<Row>
        caption="Widgets"
        rows={rows}
        failed={false}
        rowKey={(r) => r.id}
        empty="none"
        rowActions={[
          {
            key: "edit",
            label: "Edit",
            arity: "single",
            run: (rs) => ran.push(rs.map((r) => r.name)),
          },
          {
            key: "del",
            label: "Delete",
            danger: true,
            unavailable: (r) =>
              r.state === "locked" ? "This widget is locked." : null,
            run: (rs) => ran.push(rs.map((r) => r.name)),
          },
        ]}
        columns={[
          {
            key: "name",
            header: "Name",
            sortValue: (r) => r.name,
            cell: (r) => <span>{r.name}</span>,
          },
        ]}
      />,
    );
  }

  const pick = (name: string) =>
    fireEvent.click(screen.getByRole("checkbox", { name: `Select ${name}` }));

  it("⚠ rowActions IMPLIES selectable — a set of verbs with no way to choose what they act on is not a feature", () => {
    acts();
    expect(screen.getAllByRole("checkbox").length).toBeGreaterThan(0);
    expect(
      screen.getByText("Select one or more rows to act on them"),
    ).toBeTruthy();
  });

  it("⛔ THE ACTION BAR SITS ABOVE THE TABLE, NOT BELOW IT", () => {
    // The verbs are what the selection is FOR, so they belong where the eye already is — beside the rows
    // being ticked rather than past the end of them. Below, on a 25-row page, the operator selects at the
    // top and must then scroll away from their own selection to act on it.
    //
    // Asserted on DOM ORDER because CSS cannot be seen from here and a class name is not a position.
    acts();
    const bar = screen
      .getByText("Select one or more rows to act on them")
      .closest("div")!;
    const table = screen.getByRole("table");
    // DOCUMENT_POSITION_FOLLOWING (4) — the table comes AFTER the bar.
    expect(
      bar.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("a `single` verb is disabled for two rows, and says why", () => {
    acts();
    pick("alpha");
    expect(
      screen.getByRole("button", { name: "Edit" }).hasAttribute("disabled"),
    ).toBe(false);
    pick("cocoa");
    const edit = screen.getByRole("button", { name: "Edit" });
    expect(edit.hasAttribute("disabled")).toBe(true);
    // ⛔ A disabled control with no explanation is a dead end: the operator cannot tell "not allowed" from
    // "broken", and will click it again.
    expect(edit.getAttribute("title")).toMatch(/exactly one row/);
  });

  it("⭐ A MIXED SELECTION SAYS HOW MANY THE VERB WILL ACTUALLY TOUCH, BEFORE THE CLICK", () => {
    acts();
    pick("alpha");
    pick("bravo"); // locked — ineligible for Delete
    expect(screen.getByText("1 of 2")).toBeTruthy();
    expect(screen.getByText("1 of 2").getAttribute("title")).toBe(
      "This widget is locked.",
    );
  });

  it("⭐ …AND IT RUNS ON EXACTLY THE SET IT COUNTED", () => {
    // The count would be theatre if `run` still received the ineligible row. This is the assertion that
    // makes the warning mean something.
    acts();
    pick("alpha");
    pick("bravo");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(ran).toEqual([["alpha"]]);
  });

  it("a verb no selected row can take is DISABLED and carries the reason", () => {
    acts();
    pick("bravo");
    const del = screen.getByRole("button", { name: "Delete" });
    expect(del.hasAttribute("disabled")).toBe(true);
    expect(del.getAttribute("title")).toBe("This widget is locked.");
  });

  it("⚠ AND THE ORDINARY CASE STILL WORKS — an all-eligible selection shows no partial count", () => {
    // Without this, "always disabled" or "always warn" would satisfy every assertion above while making the
    // bar useless.
    acts();
    pick("alpha");
    pick("cocoa");
    expect(screen.queryByText(/^\d+ of \d+$/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(ran).toEqual([["alpha", "cocoa"]]);
  });
});

/**
 * ⛔ THE FOOTER MUST ONLY EXIST WHEN IT HAS SOMETHING TO SAY.
 *
 * The first version of "no pager when everything fits" hid the page BUTTONS and left the rows-per-page
 * control and the range behind — so a five-row table rendered "Rows per page [25]   1–5 of 5": a control
 * whose every value produces the same screen, and a range restating the obvious. On a page with three
 * tables that is more chrome than content, which is how the founder found it.
 */
describe("DataTable — the footer earns its place", () => {
  const rows = (n: number): Row[] =>
    Array.from({ length: n }, (_, i) => ({
      id: String(i),
      name: `row-${i}`,
      owner: i % 2 ? "ana@x.com" : "bo@x.com",
      state: "active",
    }));

  function t(n: number) {
    render(
      <DataTable<Row>
        caption="Widgets"
        rows={rows(n)}
        failed={false}
        rowKey={(r) => r.id}
        empty="none"
        columns={[
          {
            key: "name",
            header: "Name",
            sortValue: (r) => `${r.name} ${r.owner}`,
            cell: (r) => <span>{r.name}</span>,
          },
        ]}
      />,
    );
  }

  it("⛔ A TABLE THAT FITS SHOWS NO FOOTER AT ALL", () => {
    t(5);
    expect(screen.queryByLabelText("Rows per page")).toBeNull();
    expect(screen.queryByRole("button", { name: "Next page" })).toBeNull();
    expect(screen.queryByText(/of 5/)).toBeNull();
    // ⚠ And the rows are all there — "hide the footer" must not have become "hide the table".
    expect(screen.getAllByRole("row")).toHaveLength(6);
  });

  it("⚠ …BUT A FILTER ON THAT SAME TABLE BRINGS BACK THE COUNT", () => {
    // The narrowing is the one fact a single page still owes the operator: without it a filtered view is
    // indistinguishable from a short one.
    t(5);
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Filter Widgets" }),
      {
        target: { value: "ana@x.com" },
      },
    );
    expect(screen.getByText("2 of 5")).toBeTruthy();
    // Still no paging controls — narrowing did not create a second page.
    expect(screen.queryByLabelText("Rows per page")).toBeNull();
  });

  it("more than one page shows the full footer", () => {
    // The negative half: "never show a footer" would satisfy both assertions above and delete pagination.
    t(60);
    expect(screen.getByLabelText("Rows per page")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Next page" })).toBeTruthy();
    expect(screen.getByText("1–25 of 60")).toBeTruthy();
  });

  it("the first column is inset from the table edge — in BOTH the header and the body", () => {
    // ⚠ THE FOUNDER REPORTED THIS FIXED-BUT-INVISIBLE, AND THE CAUSE WAS A STALE SERVED BUNDLE, NOT A MISSING
    // EDIT. A test cannot catch a stale deploy — but it can make the source side unambiguous, so the next
    // time the screen and the code disagree, the code half is already answered.
    table();
    const th = screen.getByRole("columnheader", { name: /Name/ });
    expect(th.className).toContain("pl-3");
    // The body half is a SEPARATE className expression, so the header passing says nothing about it: text
    // flush against the panel border is what was actually reported, and that is a <td>.
    const firstCell = screen.getAllByRole("row")[1].querySelectorAll("td")[0];
    expect(firstCell?.className).toContain("pl-3");
  });

  it("⛔ …AND A SELECTABLE TABLE INSETS THE CHECKBOX INSTEAD, never both", () => {
    // Double-padding the first data column when a checkbox already sits to its left would push the content
    // out of line with the header of every other table. The guard is `i === 0 && !showSelect`, so this is
    // the branch that proves the condition is a condition rather than an unconditional pl-3.
    render(
      <DataTable<Row>
        caption="Selectable"
        rows={ROWS}
        rowKey={(r) => r.id}
        empty="none"
        failed={false}
        selectable
        columns={[
          { key: "name", header: "Name", cell: (r) => <span>{r.name}</span> },
        ]}
      />,
    );
    const cells = screen.getAllByRole("row")[1].querySelectorAll("td");
    expect(cells[0].className).toContain("pl-3"); // the checkbox cell carries it
    expect(cells[1].className).not.toContain("pl-3"); // the name cell does not
    // ⛔ AND THE HEADER IS ITS OWN EXPRESSION. Asserting only the <td>s left the <th> guard unchecked —
    // mutation MISSED it: weakening the header condition to a bare `i === 0` double-padded the header of
    // every selectable table while all three body assertions still passed.
    const heads = screen.getAllByRole("columnheader");
    expect(heads[0].className).toContain("pl-3"); // the checkbox header
    expect(heads[1].className).not.toContain("pl-3"); // the Name header does not repeat it
  });
});
