import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import AppAccessPagination from "../src/components/AppAccessPagination";

afterEach(cleanup);

it.each([0, 1, 10])("omits pagination for a single page of %i rows", count => {
  const onPageChange = vi.fn();
  const onPageSizeChange = vi.fn();
  render(<AppAccessPagination page={1} pageSize={20} count={count} hasNext={false} onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />);
  expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
  expect(screen.queryByRole("combobox", { name: "Rows per page" })).toBeNull();
  expect(onPageChange).not.toHaveBeenCalled();
  expect(onPageSizeChange).not.toHaveBeenCalled();
});

it("retains the size choice on an eleven-row single page after choosing a larger size", () => {
  const onPageChange = vi.fn();
  const onPageSizeChange = vi.fn();
  const props = { page: 1, count: 11, hasNext: false, onPageChange, onPageSizeChange };
  const view = render(<AppAccessPagination {...props} pageSize={20} />);
  expect(screen.getByText("1–11 shown")).toBeTruthy();
  expect(screen.queryByText("Page 1")).toBeNull();
  expect(screen.queryByRole("button", { name: "Previous page" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Next page" })).toBeNull();
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
  expect(onPageSizeChange).toHaveBeenCalledWith(50);
  view.rerender(<AppAccessPagination {...props} pageSize={50} />);
  expect(screen.getByRole("combobox", { name: "Rows per page" })).toHaveProperty("value", "50");
  expect(screen.getByText("1–11 shown")).toBeTruthy();
  expect(screen.queryByText("Page 1")).toBeNull();
  fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
  expect(onPageSizeChange).toHaveBeenLastCalledWith(10);
  expect(onPageChange).not.toHaveBeenCalled();
});

it("can advance when backend paging has more results even if filtering leaves no visible rows", () => {
  const onPageChange = vi.fn();
  render(<AppAccessPagination page={1} pageSize={20} count={0} hasNext={true} onPageChange={onPageChange} onPageSizeChange={vi.fn()} />);
  expect(screen.getByText("0 results")).toBeTruthy();
  expect(screen.getByText("Page 1")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", false);
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  expect(onPageChange).toHaveBeenCalledWith(2);
});

it.each([0, 5])("can return from a last page containing %i rows", count => {
  const onPageChange = vi.fn();
  render(<AppAccessPagination page={2} pageSize={50} count={count} hasNext={false} onPageChange={onPageChange} onPageSizeChange={vi.fn()} />);
  expect(screen.getByText(count ? "51–55 shown" : "0 results")).toBeTruthy();
  expect(screen.getByText("Page 2")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Next page" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("button", { name: "Previous page" })).toHaveProperty("disabled", false);
  fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
  expect(onPageChange).toHaveBeenCalledWith(1);
});

it("keeps page and size changes disabled while a request is busy", () => {
  const onPageChange = vi.fn();
  const onPageSizeChange = vi.fn();
  render(<AppAccessPagination page={2} pageSize={20} count={20} hasNext={true} busy onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />);
  expect(screen.getByRole("combobox", { name: "Rows per page" })).toHaveProperty("disabled", true);
  for (const name of ["Previous page", "Next page"]) {
    const button = screen.getByRole("button", { name });
    expect(button).toHaveProperty("disabled", true);
    fireEvent.click(button);
  }
  expect(onPageChange).not.toHaveBeenCalled();
  expect(onPageSizeChange).not.toHaveBeenCalled();
});

it("keeps the API offset ceiling by default while permitting a complete local list to continue", () => {
  const onPageChange = vi.fn();
  const props = { page: 501, pageSize: 20, count: 20, hasNext: true, onPageChange, onPageSizeChange: vi.fn() };
  const view = render(<AppAccessPagination {...props} />);
  const boundedNext = screen.getByRole("button", { name: "Next page" });
  expect(boundedNext).toHaveProperty("disabled", true);
  fireEvent.click(boundedNext);
  expect(onPageChange).not.toHaveBeenCalled();
  view.rerender(<AppAccessPagination {...props} maxOffset={null} />);
  const localNext = screen.getByRole("button", { name: "Next page" });
  expect(localNext).toHaveProperty("disabled", false);
  fireEvent.click(localNext);
  expect(onPageChange).toHaveBeenCalledWith(502);
});

it("reports the actual range after a short cursor page instead of assuming the preceding page was full", () => {
  const onPageChange = vi.fn();
  render(<AppAccessPagination page={2} pageSize={20} firstItem={2} count={1} hasNext={false} maxOffset={null} onPageChange={onPageChange} onPageSizeChange={vi.fn()} />);
  expect(screen.getByText("2–2 shown")).toBeTruthy();
  expect(screen.queryByText("21–21 shown")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
  expect(onPageChange).toHaveBeenCalledWith(1);
});
