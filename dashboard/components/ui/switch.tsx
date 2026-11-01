"use client";
import * as React from "react";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import { cn } from "@/lib/utils";

// checked = Blocked (red); unchecked = Allowed
export const Switch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitive.Root>, React.ComponentPropsWithoutRef<typeof SwitchPrimitive.Root>
>(({ className, ...p }, ref) => (
  <SwitchPrimitive.Root ref={ref} className={cn(
    "inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border border-transparent bg-white/15 transition-colors data-[state=checked]:bg-bad disabled:opacity-50",
    className)} {...p}>
    <SwitchPrimitive.Thumb className="block h-5 w-5 rounded-full bg-white shadow transition-transform translate-x-0.5 data-[state=checked]:translate-x-[22px]" />
  </SwitchPrimitive.Root>
));
Switch.displayName = "Switch";
