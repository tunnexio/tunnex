import { createElement, useState, type FormEvent } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EntityPicker, type PickerOption } from "../src/components/EntityPicker";
afterEach(cleanup);
const options = [{ value: "a", kind: "provider", tag: "", label: "Anthropic", icon: createElement("img", { src: "/fixture.svg", alt: "" }) }, { value: "b", kind: "provider", tag: "", label: "Gemini", unavailable: "Unavailable now" }];
describe("EntityPicker accessible selection", () => {
  it("connects keyboard focus to an option, refuses unavailable choices and closes Escape without bubbling", () => {
    const select = vi.fn(), escape = vi.fn();
    render(createElement("div", { onKeyDown: escape }, createElement(EntityPicker, { label: "Provider", options, value: "", onSelect: select })));
    const input = screen.getByRole("combobox"); fireEvent.focus(input);
    expect(document.getElementById(input.getAttribute("aria-activedescendant")!)?.textContent).toContain("Anthropic");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(document.getElementById(input.getAttribute("aria-activedescendant")!)?.textContent).toContain("Gemini");
    fireEvent.keyDown(input, { key: "Enter" }); expect(select).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "Anthropic" } }); fireEvent.keyDown(input, { key: "Enter" });
    expect(select).toHaveBeenCalledWith(options[0]); expect(input.getAttribute("aria-expanded")).toBe("false");
    fireEvent.focus(input); escape.mockClear(); fireEvent.keyDown(input, { key: "Escape" });
    expect(escape).not.toHaveBeenCalled(); expect(screen.queryByRole("listbox")).toBeNull();
  });
  it("keeps multiple same-label pickers independent and renders real option artwork", () => {
    render(createElement("div", null, ...[1, 2].map((key) => createElement(EntityPicker, { key, label: "Provider", options, value: "a", onSelect: vi.fn() }))));
    const inputs = screen.getAllByRole("combobox"); expect(inputs[0].id).not.toBe(inputs[1].id);
    expect(document.querySelectorAll('img[src="/fixture.svg"]').length).toBe(2);
  });
  it("consumes Enter for empty or unavailable results instead of submitting an enclosing form", () => {
    const submit = vi.fn(), select = vi.fn();
    render(createElement("form", { onSubmit: (e: FormEvent) => { e.preventDefault(); submit(); } }, createElement(EntityPicker, { label: "Provider", options, value: "a", onSelect: select }), createElement("button", { type: "submit" }, "Save")));
    const input = screen.getByRole("combobox"); fireEvent.focus(input);
    for (const query of ["no match", "Gemini"]) {
      fireEvent.change(input, { target: { value: query } });
      const enter = new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
      fireEvent(input, enter);
      // JSDOM omits the browser's implicit form-submit default action, so emulate
      // that action only if the component failed to cancel the key event.
      if (!enter.defaultPrevented) fireEvent.submit(input.closest("form")!);
      expect(enter.defaultPrevented).toBe(true);
    }
    expect(submit).not.toHaveBeenCalled(); expect(select).not.toHaveBeenCalled();
  });

});

it.each(["click", "enter"])("displays a committed CIDR after %s and retains a named selection for an uncommitted query", method=>{
 const home={value:"site-home",kind:"site",tag:"SITE",label:"Home lan"};
 function Draft(){const [chosen,setChosen]=useState<PickerOption>(home);return <EntityPicker label="Source" options={[home]} value={chosen.value} acceptCidr onSelect={setChosen}/>}
 render(<Draft/>);const input=screen.getByRole("combobox") as HTMLInputElement;
 fireEvent.focus(input);fireEvent.change(input,{target:{value:"192.168.1.0/24"}});fireEvent.keyDown(input,{key:"Escape"});
 expect(input.value).toBe("Home lan");
 fireEvent.focus(input);fireEvent.change(input,{target:{value:"192.168.1.0/24"}});
 if(method==="click")fireEvent.click(screen.getByRole("button",{name:/192.168.1.0\/24/}));else fireEvent.keyDown(input,{key:"Enter"});
 expect(input.value).toBe("192.168.1.0/24");expect(input.getAttribute("aria-expanded")).toBe("false");
});
it("hydrates literal CIDRs only when the picker accepts them",()=>{
 const {rerender}=render(<EntityPicker label="Source" options={[]} value="192.168.1.0/24" acceptCidr onSelect={()=>{}}/>);
 expect((screen.getByRole("combobox") as HTMLInputElement).value).toBe("192.168.1.0/24");
 rerender(<EntityPicker label="Destination" options={[]} value="missing-resource-id" onSelect={()=>{}}/>);
 expect((screen.getByRole("combobox") as HTMLInputElement).value).toBe("");
});
