import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@testing-library/react";
import { useEffect } from "react";

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      GET: vi.fn(async () => ({
        data: {
          state: "valid",
          tier: "scale",
          gateway_ceiling: null,
          org_ceiling: null,
          features: [],
        },
      })),
    },
  };
});

import { api } from "../src/lib/api";
import {
  LicenceResourceProvider,
  useLicenceResource,
} from "../src/lib/licenceResource";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function Reader() {
  const resource = useLicenceResource();
  useEffect(() => {
    void resource?.read();
  }, [resource]);
  return null;
}

describe("deployment licence resource", () => {
  it("shares one in-flight and cached read across shell consumers", async () => {
    const view = render(
      <LicenceResourceProvider>
        <Reader />
        <Reader />
      </LicenceResourceProvider>,
    );

    await waitFor(() => expect(api.GET).toHaveBeenCalledTimes(1));
    view.rerender(
      <LicenceResourceProvider>
        <Reader />
        <Reader />
        <Reader />
      </LicenceResourceProvider>,
    );
    await Promise.resolve();
    expect(api.GET).toHaveBeenCalledTimes(1);
  });
});
