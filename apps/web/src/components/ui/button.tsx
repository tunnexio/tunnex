import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

// shadcn/ui button structure, adapted to the existing Tailwind 3 token palette.
export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-focus focus-visible:ring-offset-1 focus-visible:ring-offset-surface disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
  { variants: {
    variant: {
      default: "bg-ink-heading text-surface border border-transparent shadow-sm hover:opacity-90",
      outline: "border border-line bg-surface text-ink-heading hover:bg-surface-inset",
      ghost: "text-ink-body hover:bg-surface-inset hover:text-ink-heading",
      destructive: "bg-danger text-black hover:opacity-90",
    },
    size: { default: "min-h-9 px-4 py-2", sm: "min-h-8 rounded-md px-3 py-1 text-xs", icon: "h-9 w-9" },
  }, defaultVariants: { variant: "default", size: "default" } },
);
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> { asChild?: boolean }
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(buttonVariants({ variant, size, className }))} {...props} />;
  },
);
Button.displayName = "Button";
