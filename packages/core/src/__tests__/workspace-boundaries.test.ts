import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { copyProjectToWorkspace } from "../workspace";
const roots: string[] = [];
afterEach(() => roots.splice(0).forEach(root => rmSync(root, {recursive:true, force:true})));
function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "pp-workspace-test-")); roots.push(root);
  const source = path.join(root, "source"), destination = path.join(root, "copy");
  mkdirSync(source); return {root,source,destination};
}
describe("workspace copy boundaries", () => {
  it.each(["file", "directory", "cycle"])("rejects %s symlinks rather than following them", kind => {
    const { root, source, destination } = fixture();
    const outside = path.join(root,"outside"); mkdirSync(outside);
    writeFileSync(path.join(outside,"data.txt"),"must remain outside");
    const target = kind === "cycle" ? source : kind === "directory" ? outside : path.join(outside,"data.txt");
    symlinkSync(target,path.join(source,"link"), kind === "file" ? "file" : "junction");
    expect(() => copyProjectToWorkspace(source,destination)).toThrow("cannot include symbolic links");
    expect(existsSync(path.join(destination,"link"))).toBe(false);
  });
  it("copies normal nested files and still excludes secrets", () => {
    const {source,destination} = fixture(); mkdirSync(path.join(source,"src"));
    writeFileSync(path.join(source,"src","index.ts"),"export {};");
    writeFileSync(path.join(source,".env"),"secret");
    copyProjectToWorkspace(source,destination);
    expect(readFileSync(path.join(destination,"src","index.ts"),"utf8")).toBe("export {};");
    expect(existsSync(path.join(destination,".env"))).toBe(false);
  });
});
