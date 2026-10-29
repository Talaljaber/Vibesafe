import { describe, it, expect } from "vitest";
import {
  parseDockerfile,
  parseFrom,
  parseKeyValues,
} from "../../src/detectors/utils/dockerfile.js";

describe("parseDockerfile", () => {
  it("splits stages and records FROM details", () => {
    const doc = parseDockerfile(
      [
        "ARG BASE=node:20",
        "FROM --platform=$BUILDPLATFORM node:20-alpine AS build",
        "RUN npm ci",
        "FROM build AS test",
        "FROM gcr.io/distroless/nodejs20@sha256:abc",
        "COPY --from=build /app /app",
      ].join("\n"),
    );
    expect(doc.stages).toHaveLength(3);
    expect(doc.stages[0]!.from).toMatchObject({
      image: "node:20-alpine",
      tag: "20-alpine",
      alias: "build",
      platform: "$BUILDPLATFORM",
      fromStage: false,
    });
    expect(doc.stages[1]!.from.fromStage).toBe(true);
    expect(doc.stages[2]!.from.digest).toBe("sha256:abc");
    expect(doc.instructions[0]!.stage).toBe(-1);
    expect(doc.stages[2]!.instructions.map((i) => i.keyword)).toEqual(["FROM", "COPY"]);
  });

  it("joins continuations and skips comment lines inside them", () => {
    const doc = parseDockerfile(
      [
        "FROM node:20",
        "RUN apt-get update && \\",
        "# a comment",
        "    apt-get install -y curl",
      ].join("\n"),
    );
    const run = doc.instructions[1]!;
    expect(run.args.replace(/\s+/g, " ")).toBe("apt-get update && apt-get install -y curl");
    expect([run.line, run.endLine]).toEqual([2, 4]);
  });

  it("honours the # escape= directive", () => {
    const doc = parseDockerfile(
      ["# escape=`", "FROM mcr.microsoft.com/windows", "RUN dir `", "  C:\\"].join("\n"),
    );
    expect(doc.escape).toBe("`");
    expect(doc.instructions[1]!.args.replace(/\s+/g, " ")).toBe("dir C:\\");
  });

  it("reads heredoc bodies and does not treat them as instructions", () => {
    const doc = parseDockerfile(
      [
        "FROM alpine:3.20",
        "RUN <<EOF",
        "USER root",
        "echo hi",
        "EOF",
        "COPY <<-'CONF' /etc/app.conf",
        "\tkey=value",
        "\tCONF",
        "USER app",
      ].join("\n"),
    );
    expect(doc.instructions.map((i) => i.keyword)).toEqual(["FROM", "RUN", "COPY", "USER"]);
    expect(doc.instructions[1]!.heredocs).toEqual(["USER root\necho hi"]);
    expect(doc.instructions[2]!.heredocs).toEqual(["key=value"]);
    expect(doc.instructions[3]!.line).toBe(9);
  });

  it("does not treat a here-string (<<<) as a heredoc", () => {
    const doc = parseDockerfile(["FROM alpine:3.20", 'RUN cat <<< "x"', "USER app"].join("\n"));
    expect(doc.instructions.map((i) => i.keyword)).toEqual(["FROM", "RUN", "USER"]);
  });

  it("handles CRLF", () => {
    const doc = parseDockerfile("FROM node:20\r\nUSER node\r\n");
    expect(doc.instructions.map((i) => [i.keyword, i.args])).toEqual([
      ["FROM", "node:20"],
      ["USER", "node"],
    ]);
  });
});

describe("parseFrom", () => {
  it("does not mistake a registry port for a tag", () => {
    expect(parseFrom("localhost:5000/app", new Set()).tag).toBeUndefined();
    expect(parseFrom("localhost:5000/app:1.2", new Set()).tag).toBe("1.2");
    expect(parseFrom("${BASE}", new Set()).variable).toBe(true);
  });
});

describe("parseKeyValues", () => {
  it("reads K=V pairs, quotes and the legacy form", () => {
    expect(parseKeyValues("A=1 B=\"two words\" C='x'")).toEqual([
      { key: "A", value: "1" },
      { key: "B", value: "two words" },
      { key: "C", value: "x" },
    ]);
    expect(parseKeyValues("API_KEY some value")).toEqual([{ key: "API_KEY", value: "some value" }]);
    expect(parseKeyValues("NPM_TOKEN")).toEqual([{ key: "NPM_TOKEN", value: undefined }]);
  });
});
