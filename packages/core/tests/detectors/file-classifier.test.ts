import { describe, it, expect } from "vitest";
import {
  hasUseServerDirective,
  isClientFile,
  usesServerSideDataFetching,
} from "../../src/detectors/utils/file-classifier";

describe("file-classifier", () => {
  it("detects a use server directive after leading comments", () => {
    expect(hasUseServerDirective(`// note\n/* c */\n"use server";\n`)).toBe(true);
    expect(hasUseServerDirective(`import x from "y";\n"use server";`)).toBe(false);
  });

  it("treats use server files as non-client, even under pages/", () => {
    expect(isClientFile("pages/actions.ts", `// c\n'use server';\n`)).toBe(false);
    expect(isClientFile("app/a.ts", `"use server";\n`)).toBe(false);
  });

  it("still treats use client and pages files as client", () => {
    expect(isClientFile("app/a.tsx", `"use client";\n`)).toBe(true);
    expect(isClientFile("src/pages/index.tsx", `export default 1;`)).toBe(true);
    expect(isClientFile("pages/api/x.ts", `export default 1;`)).toBe(false);
  });

  it("detects server-side data fetching exports in pages files only", () => {
    const gssp = `export async function getServerSideProps() {}`;
    expect(usesServerSideDataFetching("pages/a.tsx", gssp)).toBe(true);
    expect(usesServerSideDataFetching("pages/a.tsx", `export const getStaticProps = async () => ({});`)).toBe(true);
    expect(usesServerSideDataFetching("pages/a.tsx", `Page.getInitialProps = async () => ({});`)).toBe(true);
    expect(usesServerSideDataFetching("app/a.tsx", gssp)).toBe(false);
    expect(usesServerSideDataFetching("pages/a.tsx", `export default 1;`)).toBe(false);
  });
});
