import { FormEvent, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { extractErrorMessage } from "../lib/errors";
import { getStatusIcon } from "../lib/statusUtils";
import type { HostResources, Instance, Job } from "../lib/types";

const MACOS_CPU_MAX = 4;
const MACOS_RAM_MAX_MB = 8192;
const DEFAULT_CPU_MAX = 4;
const DEFAULT_RAM_MAX_MB = 8192;
const DEFAULT_DISK_MAX_GB = 50;
const RAM_STEP_MB = 512;
const DISK_STEP_GB = 5;

// Strip ANSI escape codes and extract the most relevant error line.
function friendlyError(raw: string): string {
  const clean = raw
    .replace(/\x1b\[[0-9;]*m/g, "")
    .replace(/\[[\d;]+m/g, "");

  // Prefer the [ERROR] line — it's the most specific
  const errMatch = clean.match(/\[ERROR\]\s+(.+?)(?=\s*\[(?:INFO|WARN|ERROR)\]|$)/s);
  if (errMatch) {
    return errMatch[1]
      .replace(/\s+at\s+\/\S+/g, "")   // remove filesystem paths
      .replace(/\s{2,}/g, " ")
      .trim();
  }

  // Fallback: strip log-level tags and return cleaned text
  return clean.replace(/\[(?:INFO|WARN|ERROR)\]\s*/g, "").trim();
}

function buildSteppedOptions(min: number, max: number, step: number): number[] {
  if (max < min) return [];

  const options: number[] = [];
  for (let value = min; value <= max; value += step) {
    options.push(value);
  }

  if (options[options.length - 1] !== max) {
    options.push(max);
  }

  return options;
}

function clampSelection(current: number, options: number[]): number {
  if (options.length === 0 || options.includes(current)) {
    return current;
  }

  const lowerOptions = options.filter((option) => option <= current);
  if (lowerOptions.length > 0) {
    return lowerOptions[lowerOptions.length - 1];
  }

  return options[0];
}

export function CreatePage() {
  const [name, setName] = useState("");
  const [clawType, setClawType] = useState("picoclaw");
  const [guestOs, setGuestOs] = useState("");
  const [platform, setPlatform] = useState("");
  const [clawTypes, setClawTypes] = useState<string[]>([]);
  const [created, setCreated] = useState<Instance | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [tools, setTools] = useState({
    codex: true,
    claudeCode: true,
    opencode: true,
  });
  const [cpuCores, setCpuCores] = useState(2);
  const [ramMb, setRamMb] = useState(2048);
  const [diskGb, setDiskGb] = useState(10);
  const [resources, setResources] = useState<HostResources | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // Detect server platform on mount
  useEffect(() => {
    fetch("/healthz")
      .then(r => { if (!r.ok) throw new Error("healthz failed"); return r.json(); })
      .then(d => {
        const p = d.platform || "";
        setPlatform(p);
        setGuestOs(p.includes("macos") ? "macos" : "linux");
      })
      .catch(() => setGuestOs("linux"));
  }, []);

  // Fetch host resource budget on mount
  useEffect(() => {
    api.getResources()
      .then(setResources)
      .catch(() => setResources(null));
  }, []);

  // Fetch available claw types on mount (D1: use /api/v1/claws filtered by ready)
  useEffect(() => {
    api.listClaws()
      .then(claws => {
        const ready = claws.filter(c => c.status === "ready").map(c => c.name);
        setClawTypes(ready);
        if (ready.length > 0 && !ready.includes(clawType)) {
          setClawType(ready[0]);
        }
      })
      .catch(err => {
        console.error("Failed to fetch claws:", err);
        // D5: empty fallback, not hardcoded 6 claws
        setClawTypes([]);
      });
  }, []);

  const isMacHost = platform.includes("macos");
  const cpuMax = resources
    ? Math.max(0, Math.min(resources.available.cpu_cores, isMacHost ? MACOS_CPU_MAX : resources.available.cpu_cores))
    : (isMacHost ? MACOS_CPU_MAX : DEFAULT_CPU_MAX);
  const ramMaxMb = resources
    ? Math.max(0, Math.min(resources.available.ram_mb, isMacHost ? MACOS_RAM_MAX_MB : resources.available.ram_mb))
    : DEFAULT_RAM_MAX_MB;
  const diskMaxGb = resources ? Math.max(0, resources.available.disk_gb) : DEFAULT_DISK_MAX_GB;

  const cpuOptions = buildSteppedOptions(1, cpuMax, 1);
  const ramOptions = buildSteppedOptions(512, ramMaxMb, RAM_STEP_MB);
  const diskOptions = buildSteppedOptions(5, diskMaxGb, DISK_STEP_GB);

  useEffect(() => {
    if (!resources) return;

    if (cpuOptions.length > 0) {
      setCpuCores((current) => clampSelection(current, cpuOptions));
    }
    if (ramOptions.length > 0) {
      setRamMb((current) => clampSelection(current, ramOptions));
    }
    if (!isMacHost && diskOptions.length > 0) {
      setDiskGb((current) => clampSelection(current, diskOptions));
    }
  }, [resources, isMacHost, cpuMax, ramMaxMb, diskMaxGb]);

  // Poll for job status when instance is being provisioned
  const pollActive = useRef(false);
  useEffect(() => {
    if (!created || !isPolling || !job) return;

    const pollInterval = setInterval(async () => {
      if (pollActive.current) return;
      pollActive.current = true;
      try {
        // Check job status
        const jobStatus = await api.getJob(job.id);
        setJob(jobStatus);

        // Also check instance status
        const instanceStatus = await api.getInstanceStatus(created.id);
        if (instanceStatus.instance) {
          setCreated(instanceStatus.instance);
        }

        // Stop polling if job is complete or failed
        if (jobStatus.status === "completed" || jobStatus.status === "failed") {
          setIsPolling(false);
          if (jobStatus.status === "failed") {
            setError(jobStatus.error || "Provisioning failed");
          }
        }
      } catch (err) {
        console.error("Polling error:", err);
      } finally {
        pollActive.current = false;
      }
    }, 2000); // Poll every 2 seconds

    return () => clearInterval(pollInterval);
  }, [created, isPolling, job]);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setCreated(null);
    setJob(null);
    setIsPolling(false);

    try {
      const selectedTools: string[] = [];
      if (tools.codex) selectedTools.push("codex");
      if (tools.claudeCode) selectedTools.push("claude-code");
      if (tools.opencode) selectedTools.push("opencode");
      const result = await api.createInstance(
        name, clawType, selectedTools, guestOs,
        cpuCores, ramMb,
        isMacHost ? undefined : diskGb,
      );
      setCreated(result.instance);
      
      // If async creation (job returned)
      if (result.job_id) {
        setJob({
          id: result.job_id,
          type: "create_instance",
          status: "pending",
          instance_id: result.instance.id,
          message: result.message || "Queued for provisioning",
          created_at: new Date().toISOString(),
        });
        setIsPolling(true);
      }
      
      setName("");
    } catch (err) {
      setError(friendlyError(extractErrorMessage(err, "failed to create instance")));
    } finally {
      setLoading(false);
    }
  };

  const getStatusText = () => {
    if (!created) return "";
    
    if (created.status === "provisioning") {
      if (job?.status === "running") {
        return job.message || "Provisioning in progress...";
      }
      if (job?.status === "pending") {
        return "Waiting to start provisioning...";
      }
      return "Provisioning...";
    }
    
    if (created.status === "active") {
      return "Instance is active and ready";
    }
    
    if (created.status === "failed") {
      return created.provisioning_error || "Provisioning failed";
    }
    
    return `Status: ${created.status}`;
  };

  return (
    <section className="page-section createpage">
      <header className="page-header">
        <p className="path">~/soyeht/admin/create</p>
        <h1>create</h1>
        <p className="subtitle">// local provisioning for new instances</p>
      </header>

      {clawTypes.length === 0 && !loading && (
        <p className="muted">
          no claws installed.{" "}
          <a href="/claws">install one from the claw store</a> first.
        </p>
      )}

      <form className="create-form" onSubmit={handleSubmit}>
        <label htmlFor="claw-type">claw-type</label>
        <select 
          id="claw-type" 
          value={clawType} 
          onChange={(e) => setClawType(e.target.value)}
          disabled={loading || isPolling}
        >
          {clawTypes.map((option) => (
            <option value={option} key={option}>
              {option}
            </option>
          ))}
        </select>

        {isMacHost && (
          <>
            <label htmlFor="guest-os">guest os</label>
            <select
              id="guest-os"
              value={guestOs}
              onChange={(e) => setGuestOs(e.target.value)}
              disabled={loading || isPolling}
            >
              <option value="macos">macOS (max 2 per host)</option>
              <option value="linux">Linux (no limit)</option>
            </select>
          </>
        )}

        <fieldset className="resources-fieldset" disabled={loading || isPolling}>
          <legend>resources</legend>
          <label htmlFor="cpu-cores">
            cpu cores
            {resources && <span className="resource-hint"> ({resources.available.cpu_cores} of {resources.budget.cpu_cores} available)</span>}
          </label>
          <select
            id="cpu-cores"
            value={cpuOptions.includes(cpuCores) ? cpuCores : ""}
            onChange={(e) => setCpuCores(Number(e.target.value))}
            disabled={loading || isPolling || cpuOptions.length === 0}
          >
            {cpuOptions.length === 0 ? (
              <option value="">unavailable</option>
            ) : cpuOptions.map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>

          <label htmlFor="ram-mb">
            ram (mb)
            {resources && <span className="resource-hint"> ({resources.available.ram_mb} of {resources.budget.ram_mb} mb available)</span>}
          </label>
          <select
            id="ram-mb"
            value={ramOptions.includes(ramMb) ? ramMb : ""}
            onChange={(e) => setRamMb(Number(e.target.value))}
            disabled={loading || isPolling || ramOptions.length === 0}
          >
            {ramOptions.length === 0 ? (
              <option value="">unavailable</option>
            ) : ramOptions.map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>

          {!isMacHost && (
            <>
              <label htmlFor="disk-gb">
                disk (gb)
                {resources && <span className="resource-hint"> ({resources.available.disk_gb} gb free)</span>}
              </label>
              <select
                id="disk-gb"
                value={diskOptions.includes(diskGb) ? diskGb : ""}
                onChange={(e) => setDiskGb(Number(e.target.value))}
                disabled={loading || isPolling || diskOptions.length === 0}
              >
                {diskOptions.length === 0 ? (
                  <option value="">unavailable</option>
                ) : diskOptions.map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            </>
          )}
        </fieldset>

        <label htmlFor="instance-name">name</label>
        <input
          id="instance-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. user-gil"
          required
          disabled={loading || isPolling}
        />

        <fieldset className="tools-fieldset" disabled={loading || isPolling}>
          <legend>ai coding tools</legend>
          <label className="tool-checkbox">
            <input
              type="checkbox"
              checked={tools.codex}
              onChange={(e) => setTools({ ...tools, codex: e.target.checked })}
            />
            <span className="tool-info">
              <strong>Codex</strong>
              <span className="tool-desc">OpenAI coding agent</span>
            </span>
          </label>
          <label className="tool-checkbox">
            <input
              type="checkbox"
              checked={tools.claudeCode}
              onChange={(e) => setTools({ ...tools, claudeCode: e.target.checked })}
            />
            <span className="tool-info">
              <strong>Claude Code</strong>
              <span className="tool-desc">Anthropic coding agent</span>
            </span>
          </label>
          <label className="tool-checkbox">
            <input
              type="checkbox"
              checked={tools.opencode}
              onChange={(e) => setTools({ ...tools, opencode: e.target.checked })}
            />
            <span className="tool-info">
              <strong>OpenCode</strong>
              <span className="tool-desc">Open-source coding agent</span>
            </span>
          </label>
        </fieldset>

        {error && <p className="form-error">{error}</p>}

        <button type="submit" disabled={loading || isPolling}>
          {loading ? "creating..." : isPolling ? "provisioning..." : "create-instance"}
        </button>
      </form>

      {created && (
        <article className="create-result">
          <strong>instance {created.status === "provisioning" ? "creating" : "created"}</strong>
          <p>name: {created.name}</p>
          <p>type: {created.claw_type}</p>
          <p>container: {created.container}</p>
          <p className="status-line">
            {getStatusIcon(created.status)} {getStatusText()}
            {isPolling && <span className="spinner" />}
          </p>
          {job && (
            <p className="job-info">
              job: {job.id} ({job.status})
            </p>
          )}
        </article>
      )}
    </section>
  );
}
