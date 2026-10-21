import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import App from "../src/App";
import { StatusBadge } from "../src/components/StatusBadge";

describe("Frontend UI Tests", () => {
  it("renders the AegisSOC AI authentication screen initially", () => {
    render(<App />);
    expect(screen.getByText(/AegisSOC AI/i)).toBeDefined();
    expect(screen.getByText(/Evidence-Grounded Autonomous Security Operations/i)).toBeDefined();
    expect(screen.getByRole("button", { name: /Sign In/i })).toBeDefined();
    expect(screen.getByRole("button", { name: /Onboard Tenant/i })).toBeDefined();
  });

  it("toggles to tenant onboarding form", () => {
    render(<App />);
    const onboardBtn = screen.getByRole("button", { name: /Onboard Tenant/i });
    fireEvent.click(onboardBtn);
    expect(screen.getByText(/Organization \/ Tenant Name/i)).toBeDefined();
    expect(screen.getByText(/Initial Security Role/i)).toBeDefined();
  });

  it("renders StatusBadge with correct casing and labels", () => {
    render(<StatusBadge label="CRITICAL" variant="severity" />);
    expect(screen.getByText("CRITICAL")).toBeDefined();
  });
});
