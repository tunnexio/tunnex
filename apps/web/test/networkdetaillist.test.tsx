import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { NetworkDetailList } from "../src/components/NetworkDetailList";
afterEach(cleanup);
it("bounds large inventories and searches across pages", () => {
 const items = Array.from({length: 13}, (_, i) => `Gateway ${i + 1}`);
 render(<NetworkDetailList label="Gateways" items={items} searchText={item => item} renderItem={item => <li key={item}>{item}</li>} />);
 expect(screen.getAllByRole("listitem")).toHaveLength(5);
 fireEvent.click(screen.getByRole("button", {name:"Next gateways"}));
 expect(screen.getByText("Gateway 6")).toBeTruthy();
 fireEvent.change(screen.getByRole("textbox", {name:"Search Gateways"}), {target:{value:"Gateway 13"}});
 expect(screen.getAllByRole("listitem")).toHaveLength(1);
 expect(screen.getByText("Gateway 13")).toBeTruthy();
 fireEvent.change(screen.getByRole("textbox", {name:"Search Gateways"}), {target:{value:""}});
 expect(screen.getByText("Gateway 1")).toBeTruthy();
});
it("clamps pagination when rows are removed", () => {
 const props = {label:"Ranges", searchText:(item:string)=>item, renderItem:(item:string)=><li key={item}>{item}</li>};
 const items = Array.from({length:6},(_,i)=>`Range ${i}`);
 const view=render(<NetworkDetailList {...props} items={items}/>);
 fireEvent.click(screen.getByRole("button",{name:"Next ranges"}));
 view.rerender(<NetworkDetailList {...props} items={items.slice(0,5)}/>);
 expect(screen.getByText("Range 0")).toBeTruthy();
 expect(screen.queryByRole("button",{name:"Next ranges"})).toBeNull();
});
