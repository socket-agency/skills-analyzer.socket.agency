import { ClipboardPaste, GitBranch, Loader2, Radar, Upload } from "lucide-react";
import * as React from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { EXAMPLES, type ScanExample } from "@/lib/examples";
import { cn } from "@/lib/utils";

export type ScanMode = "text" | "zip" | "git";

const KIND_OPTIONS = [
  { value: "skill", label: "SKILL.md (skill)" },
  { value: "agents", label: "AGENTS.md (agents)" },
  { value: "claude_md", label: "CLAUDE.md (memory)" },
] as const;

export interface ScanFormProps {
  busy: boolean;
  onSubmit: (form: FormData) => void;
}

/** The three-mode submission panel: paste text, upload a .zip, or scan a git URL. */
export function ScanForm({ busy, onSubmit }: ScanFormProps) {
  const [mode, setMode] = React.useState<ScanMode>("text");
  const [content, setContent] = React.useState("");
  const [kindHint, setKindHint] = React.useState<string>("skill");
  const [filename, setFilename] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [file, setFile] = React.useState<File | null>(null);

  function loadExample(ex: ScanExample) {
    setMode("text");
    setContent(ex.content);
    setKindHint(ex.kind);
    setFilename(ex.filename);
  }

  function submit() {
    const form = new FormData();
    form.set("mode", mode);
    if (mode === "text") {
      form.set("content", content);
      form.set("kind_hint", kindHint);
      if (filename.trim()) form.set("filename", filename.trim());
    } else if (mode === "zip") {
      if (!file) return;
      form.set("file", file, file.name);
    } else {
      form.set("url", url.trim());
    }
    onSubmit(form);
  }

  const canSubmit =
    !busy &&
    ((mode === "text" && content.trim().length > 0) ||
      (mode === "zip" && file !== null) ||
      (mode === "git" && url.trim().length > 0));

  return (
    <div className="rounded-lg border border-line bg-panel/80 p-5 backdrop-blur-sm">
      <Tabs value={mode} onValueChange={(v) => setMode(v as ScanMode)}>
        <TabsList>
          <TabsTrigger value="text">
            <ClipboardPaste className="size-3.5" /> Paste
          </TabsTrigger>
          <TabsTrigger value="zip">
            <Upload className="size-3.5" /> Upload
          </TabsTrigger>
          <TabsTrigger value="git">
            <GitBranch className="size-3.5" /> Git URL
          </TabsTrigger>
        </TabsList>

        <TabsContent value="text" className="mt-4 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-faint">
              Load example
            </span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.id}
                type="button"
                onClick={() => loadExample(ex)}
                className={cn(
                  "rounded border px-2 py-1 font-mono text-[11px] transition-colors",
                  ex.malicious
                    ? "border-sev-critical/40 bg-sev-critical/10 text-sev-critical hover:bg-sev-critical/20"
                    : "border-scan/40 bg-scan/10 text-scan hover:bg-scan/20",
                )}
              >
                {ex.malicious ? "⚠ " : "✓ "}
                {ex.label}
              </button>
            ))}
          </div>
          <Textarea
            aria-label="Artifact content"
            placeholder={"---\nname: my-skill\ndescription: ...\n---\nPaste a SKILL.md / AGENTS.md / CLAUDE.md here."}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            spellCheck={false}
          />
          <div className="flex flex-wrap items-end gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="kind">Artifact kind</Label>
              <select
                id="kind"
                value={kindHint}
                onChange={(e) => setKindHint(e.target.value)}
                className="h-10 rounded-md border border-line bg-canvas/70 px-3 font-mono text-[13px] text-ink focus-visible:border-scan/50 focus-visible:outline-none"
              >
                {KIND_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value} className="bg-panel">
                    {o.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-1 flex-col gap-1.5">
              <Label htmlFor="filename">Filename (optional)</Label>
              <Input
                id="filename"
                placeholder="SKILL.md"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
              />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="zip" className="mt-4 space-y-3">
          <Label htmlFor="zipfile">Skill bundle (.zip)</Label>
          <Input
            id="zipfile"
            type="file"
            accept=".zip,application/zip"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          {file ? (
            <p className="font-mono text-xs text-muted">
              {file.name} · {(file.size / 1024).toFixed(1)} KB
            </p>
          ) : (
            <p className="font-mono text-xs text-faint">
              A zipped skill/agent directory (manifest + scripts + references).
            </p>
          )}
        </TabsContent>

        <TabsContent value="git" className="mt-4 space-y-3">
          <Label htmlFor="giturl">Remote git URL</Label>
          <Input
            id="giturl"
            placeholder="https://github.com/owner/skill-repo.git"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <p className="font-mono text-xs text-faint">
            Cloned shallow & read-only. Local/file:// paths are rejected.
          </p>
        </TabsContent>
      </Tabs>

      <div className="mt-5 flex justify-end">
        <Button onClick={submit} disabled={!canSubmit} size="lg">
          {busy ? <Loader2 className="animate-spin" /> : <Radar />}
          {busy ? "Scanning…" : "Run scan"}
        </Button>
      </div>
    </div>
  );
}
