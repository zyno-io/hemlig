import { describe, expect, it, vi } from "vitest";
import { useCursorPages } from "./useCursorPages";

describe("useCursorPages", () => {
  it("chases cursors through server-filtered empty pages", async () => {
    // The catalog query filters after a bounded read, so an empty page with a
    // cursor still outstanding does not mean there is nothing to find.
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: [], nextCursor: "c1" })
      .mockResolvedValueOnce({ items: [], nextCursor: "c2" })
      .mockResolvedValueOnce({ items: ["found"], nextCursor: "c3" });

    const pages = useCursorPages<string>(fetchPage);
    await pages.loadMore();

    expect(fetchPage).toHaveBeenCalledTimes(3);
    expect(pages.items.value).toEqual(["found"]);
    expect(pages.exhausted.value).toBe(false);
  });

  it("only reports exhaustion when the cursor is absent", async () => {
    const pages = useCursorPages<string>(async () => ({ items: [] }));
    await pages.loadMore();
    expect(pages.exhausted.value).toBe(true);
  });

  it("stops at the hop budget so one click cannot write unbounded audit records", async () => {
    const fetchPage = vi.fn(async () => ({ items: [] as string[], nextCursor: "more" }));
    const pages = useCursorPages<string>(fetchPage, 3);

    await pages.loadMore();

    expect(fetchPage).toHaveBeenCalledTimes(3);
    expect(pages.exhausted.value).toBe(false);
  });

  it("resets accumulated pages when filters change", async () => {
    const pages = useCursorPages<string>(async () => ({ items: ["a"] }));
    await pages.loadMore();
    expect(pages.items.value).toHaveLength(1);

    pages.reset();

    expect(pages.items.value).toHaveLength(0);
    expect(pages.exhausted.value).toBe(false);
  });
});
