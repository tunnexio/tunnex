import {useState} from "react";
import {afterEach,expect,it} from "vitest";
import {cleanup,fireEvent,render,screen} from "@testing-library/react";
import {DateTimeInput} from "../src/components/DateTimeInput";
afterEach(cleanup);
function Demo(){const [v,set]=useState('2026-09-05T11:54');return <DateTimeInput type="datetime-local" aria-label="Expiry" value={v} onChange={e=>set(e.target.value)}/>;}
it('applies a selected local date and time only on Apply',()=>{
 render(<Demo/>);fireEvent.click(screen.getByRole('button',{name:'Choose date and time'}));
 fireEvent.click(screen.getByRole('button',{name:'2026-09-09'}));
 fireEvent.change(screen.getByRole('combobox',{name:'Hour'}),{target:{value:'16'}});
 expect((screen.getByLabelText('Expiry') as HTMLInputElement).value).toBe('2026-09-05T11:54');
 fireEvent.click(screen.getByRole('button',{name:'Apply'}));
 expect((screen.getByLabelText('Expiry') as HTMLInputElement).value).toBe('2026-09-09T16:54');
});
it('cancels a draft without changing the saved field',()=>{
 render(<Demo/>);fireEvent.click(screen.getByRole('button',{name:'Choose date and time'}));fireEvent.click(screen.getByRole('button',{name:'2026-09-10'}));fireEvent.click(screen.getByRole('button',{name:'Cancel'}));expect((screen.getByLabelText('Expiry') as HTMLInputElement).value).toBe('2026-09-05T11:54');
});
it('disables calendar days outside the field limits',()=>{
 render(<DateTimeInput type="date" value="2026-09-05" min="2026-09-03" max="2026-09-08" readOnly={false} onChange={()=>{}}/>);fireEvent.click(screen.getByRole('button',{name:'Choose date and time'}));expect((screen.getByRole('button',{name:'2026-09-02'}) as HTMLButtonElement).disabled).toBe(true);expect((screen.getByRole('button',{name:'2026-09-09'}) as HTMLButtonElement).disabled).toBe(true);
});
it('keeps only one calendar open and dismisses on outside pointer input',()=>{
 render(<><DateTimeInput type="date" aria-label="From"/><DateTimeInput type="date" aria-label="To"/></>);
 const triggers=screen.getAllByRole('button',{name:'Choose date and time'});
 fireEvent.click(triggers[0]);
 fireEvent.click(triggers[1]);
 expect(triggers[0].getAttribute('aria-expanded')).toBe('false');
 expect(triggers[1].getAttribute('aria-expanded')).toBe('true');
 expect(screen.getAllByRole('group',{name:'Date and time picker'})).toHaveLength(1);
 fireEvent.pointerDown(document.body);
 expect(screen.queryByRole('group',{name:'Date and time picker'})).toBeNull();
});
