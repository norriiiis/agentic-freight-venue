/**
 * The scheduler: every periodic duty the venue has, named, with a movable
 * clock. Production runs this on a job runner; the simulator triggers jobs by
 * name with a chosen `now` (renewal deadlines, pre-pickup checks). A job that
 * throws is logged and retried on its next tick; one job never blocks another.
 */
export interface Job {
  name: string;
  everyMs: number;
  run: (now: Date) => Promise<unknown>;
}

export interface JobStatus {
  name: string;
  everyMs: number;
  runs: number;
  lastRunAt?: string;
  lastDurationMs?: number;
  lastError?: string;
  running: boolean;
}

export class Scheduler {
  private timers = new Map<string, NodeJS.Timeout>();
  private status = new Map<string, JobStatus>();
  private jobs = new Map<string, Job>();
  constructor(private readonly log: (line: string) => void = () => {}) {}

  add(job: Job) {
    this.jobs.set(job.name, job);
    this.status.set(job.name, { name: job.name, everyMs: job.everyMs, runs: 0, running: false });
    return this;
  }

  start() {
    for (const job of this.jobs.values()) {
      if (this.timers.has(job.name)) continue;
      const t = setInterval(() => { this.runNow(job.name).catch(() => {}); }, job.everyMs);
      t.unref();
      this.timers.set(job.name, t);
    }
  }

  stop() {
    for (const t of this.timers.values()) clearInterval(t);
    this.timers.clear();
  }

  /** Run one job now, optionally at a chosen moment (the simulator moves the clock; standing checks still use real time). */
  async runNow(name: string, now = new Date()): Promise<{ ok: boolean; result?: unknown; error?: string }> {
    const job = this.jobs.get(name);
    const st = this.status.get(name);
    if (!job || !st) return { ok: false, error: `unknown job ${name}` };
    if (st.running) return { ok: false, error: "already running" };
    st.running = true;
    const started = Date.now();
    try {
      const result = await job.run(now);
      st.runs++; st.lastRunAt = new Date().toISOString(); st.lastDurationMs = Date.now() - started; st.lastError = undefined;
      return { ok: true, result };
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      st.runs++; st.lastRunAt = new Date().toISOString(); st.lastDurationMs = Date.now() - started; st.lastError = error;
      this.log(`[jobs] ${name}: ${error}`);
      return { ok: false, error };
    } finally {
      st.running = false;
    }
  }

  list(): JobStatus[] {
    return [...this.status.values()];
  }
}
