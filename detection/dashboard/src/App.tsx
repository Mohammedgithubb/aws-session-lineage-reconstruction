import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { LineChart, Line, XAxis, YAxis, ReferenceLine, ResponsiveContainer, Tooltip, CartesianGrid } from "recharts";
import type { Summary, Session } from "./types";

const METHODS: [string, string][] = [["M1", "Behaviour baseline"], ["M2", "API sequence"], ["M3", "Graph anomaly"], ["M4", "Honeytokens"], ["M5", "Suppression (ISCA-DS)"]];
const STATE_CLASS: Record<string, string> = { Normal: "normal", Watch: "watch", Suspicious: "susp", Compromised: "comp" };
const hhmm = (t: number) => new Date(t * 1000).toISOString().slice(11, 19);
const short = (k: string) => (k ? k.slice(0, 4) + "…" + k.slice(-6) : "-");

function useJSON<T>(url: string | null, ms: number) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    if (!url) { setData(null); return; }
    let live = true;
    const load = () => fetch(url).then(r => r.ok ? r.json() : Promise.reject()).then(d => { if (live) { setData(d); setErr(false); } }).catch(() => live && setErr(true));
    load();
    const id = setInterval(load, ms);
    return () => { live = false; clearInterval(id); };
  }, [url, ms]);
  return { data, err };
}

export default function App() {
  const { data: sum, err } = useJSON<Summary>("/api/summary", 1000);
  const [sel, setSel] = useState<string | null>(null);
  const topKey = sum?.top?.[0]?.key ?? null;
  const key = sel ?? topKey;
  const { data: ses } = useJSON<Session>(key ? `/api/session/${key}` : null, 1500);

  return (
    <div className="app">
      <Header sum={sum} err={err} />
      <main>
        <aside className="col left">
          <Panel title="Alerts" sub="newest first">
            {!sum?.alerts?.length && <Empty text={sum?.mode === "learn" ? "Learning normal behaviour. No alerts in learn mode." : "No alerts yet."} />}
            {sum?.alerts?.map((a, i) => (
              <button key={i} className={"alert " + (a.key === key ? "on" : "")} onClick={() => setSel(a.key)}>
                <span className={"dot " + STATE_CLASS[a.state]} />
                <div className="alert-body">
                  <div className="row"><b>{a.identity}</b><span className={"badge " + STATE_CLASS[a.state]}>{a.state}</span></div>
                  <div className="muted small">{hhmm(a.t)} UTC · {short(a.key)} · belief {a.bel.toFixed(2)}</div>
                  <div className="chips">{a.methods.map(m => <span key={m} className="chip">{m}</span>)}</div>
                </div>
              </button>
            ))}
          </Panel>
          <Panel title="Sessions by risk">
            {sum?.top?.map(s => (
              <button key={s.key} className={"srow " + (s.key === key ? "on" : "")} onClick={() => setSel(s.key)}>
                <span className={"dot " + STATE_CLASS[s.state]} />
                <span className="grow"><b>{s.identity}</b> <span className="muted small">{short(s.key)}</span></span>
                <Meter v={s.bel} />
              </button>
            ))}
          </Panel>
        </aside>
        <section className="col mid">{ses ? <SessionView s={ses} /> : <Panel title="Session"><Empty text="Waiting for sessions…" /></Panel>}</section>
        <aside className="col right">
          <Panel title="Why it was flagged" sub="evidence from each method">
            {ses ? <Why s={ses} /> : <Empty text="Select a session" />}
          </Panel>
          <Panel title="Live event stream" sub="last 25 API calls">
            <div className="stream">
              {sum?.recent?.map((e, i) => (
                <div key={i} className={"ev " + (e.error ? "err" : "")}>
                  <span className="mono muted">{e.time?.slice(11, 19)}</span>
                  <span className="mono">{e.token}</span>
                  <span className="muted small">{e.identity}{e.error ? " · " + e.error : ""}</span>
                </div>
              ))}
            </div>
          </Panel>
        </aside>
      </main>
    </div>
  );
}

function Header({ sum, err }: { sum: Summary | null; err: boolean }) {
  const mode = !sum ? "connecting" : !sum.live ? "replay (synthetic data)" : sum.mode === "learn" ? "live · learning normal" : "live · detecting";
  return (
    <header>
      <div className="brand"><div className="logo">◆</div><div><div className="title">Live Identity Threat Detection</div><div className="subtitle">AWS STS sessions · CloudTrail · PW_25_NS_02</div></div></div>
      <span className={"mode " + (err ? "off" : sum?.live ? "live" : "replay")}>{err ? "detector offline" : mode}</span>
      <div className="stats">
        <Stat n={sum?.events ?? 0} label="events" />
        <Stat n={sum?.sessions ?? 0} label="sessions" />
        <Stat n={sum?.counts?.Watch ?? 0} label="watch" cls="watch" />
        <Stat n={sum?.counts?.Suspicious ?? 0} label="suspicious" cls="susp" />
        <Stat n={sum?.counts?.Compromised ?? 0} label="compromised" cls="comp" />
      </div>
      {sum?.jobs && <div className="jobs small"><div>S2 · {sum.jobs.S2}</div><div>S3 · {sum.jobs.S3}</div></div>}
    </header>
  );
}

function SessionView({ s }: { s: Session }) {
  const data = useMemo(() => s.history.map(([t, b]) => ({ t, b })), [s.history]);
  const belS = 0.9 * s.m_S;   // M5 reliability 0.9 times its mass on Suppressed
  return (
    <>
      <Panel title={s.identity} sub={`session ${s.key}`} right={<span className={"badge big " + STATE_CLASS[s.state]}>{s.state}</span>}>
        <div className="kpis">
          <div className="kpi"><div className="kv">{s.bel.toFixed(3)}</div><div className="kl">Bel(Compromised)</div></div>
          <div className="kpi"><div className="kv">{belS.toFixed(2)}</div><div className="kl">Bel(Suppressed)</div></div>
          <div className="kpi"><div className="kv">{s.n}</div><div className="kl">events in session</div></div>
          <div className="kpi"><div className="kv sm">{s.net}</div><div className="kl">first network · {s.uaf}</div></div>
        </div>
        <div className="chart">
          <ResponsiveContainer width="100%" height={210}>
            <LineChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: -18 }}>
              <CartesianGrid stroke="#eef1f2" vertical={false} />
              <XAxis dataKey="t" tickFormatter={hhmm} tick={{ fontSize: 11, fill: "#6b7780" }} minTickGap={40} />
              <YAxis domain={[0, 1]} ticks={[0, 0.3, 0.6, 0.9, 1]} tick={{ fontSize: 11, fill: "#6b7780" }} />
              <Tooltip labelFormatter={(t) => hhmm(Number(t)) + " UTC"} formatter={(v: number) => [v.toFixed(3), "belief"]} />
              <ReferenceLine y={0.3} stroke="#d99a3d" strokeDasharray="4 4" label={{ value: "Watch", position: "insideTopRight", fontSize: 10, fill: "#b57a22" }} />
              <ReferenceLine y={0.6} stroke="#d0632f" strokeDasharray="4 4" label={{ value: "Suspicious · seal", position: "insideTopRight", fontSize: 10, fill: "#c0562a" }} />
              <ReferenceLine y={0.9} stroke="#b5343c" strokeDasharray="4 4" label={{ value: "Compromised · respond", position: "insideTopRight", fontSize: 10, fill: "#b5343c" }} />
              <Line type="stepAfter" dataKey="b" stroke="#1f6f78" strokeWidth={2.5} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="mbars">
          {METHODS.map(([m, label]) => (
            <div key={m} className="mbar">
              <div className="row small"><b>{m}</b><span className="grow" /><span className="mono">{(s.mass[m] ?? 0).toFixed(2)}</span></div>
              <div className="muted small mlabel">{label}</div>
              <div className="track"><div className={"fill " + m} style={{ width: `${Math.min((s.mass[m] ?? 0) / 0.95, 1) * 100}%` }} /></div>
            </div>
          ))}
        </div>
        {(s.sealed || s.response) && (
          <div className="actions">
            {s.sealed && <div><b>Evidence sealed</b> <span className="muted">→ {s.sealed}</span></div>}
            {s.response && <div><b>Response</b> <span className="muted">→ {s.response}</span></div>}
          </div>
        )}
      </Panel>
      <Panel title="Events in this session" sub="oldest first">
        <div className="table">
          <div className="tr th"><span>time (UTC)</span><span>call</span><span>network</span><span>tool</span><span>result</span></div>
          {s.events.slice(-60).map(e => (
            <div key={e.id} className={"tr " + (e.error ? "err" : "")}>
              <span className="mono">{e.time?.slice(11, 19)}</span><span className="mono">{e.token}</span><span>{e.net}</span><span>{e.uaf}</span>
              <span>{e.error ?? "ok"}</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}

function Why({ s }: { s: Session }) {
  const any = METHODS.some(([m]) => (s.reasons[m] ?? []).length);
  if (!any) return <Empty text="No method has found anything unusual in this session." />;
  return (
    <div className="why">
      {METHODS.map(([m, label]) => (s.reasons[m] ?? []).length ? (
        <div key={m} className="whyblock">
          <div className="row"><span className={"chip " + m}>{m}</span><b>{label}</b><span className="grow" /><span className="mono small">m = {(s.mass[m] ?? 0).toFixed(2)}</span></div>
          <ul>{[...new Set(s.reasons[m])].slice(0, 5).map((r, i) => <li key={i}>{r}</li>)}</ul>
        </div>
      ) : null)}
    </div>
  );
}

function Panel({ title, sub, right, children }: { title: string; sub?: string; right?: ReactNode; children: ReactNode }) {
  return <div className="panel"><div className="ph"><div><div className="pt">{title}</div>{sub && <div className="ps">{sub}</div>}</div>{right}</div><div className="pb">{children}</div></div>;
}
const Empty = ({ text }: { text: string }) => <div className="empty">{text}</div>;
const Stat = ({ n, label, cls = "" }: { n: number; label: string; cls?: string }) => <div className={"stat " + cls}><div className="sn">{n}</div><div className="sl">{label}</div></div>;
const Meter = ({ v }: { v: number }) => <span className="meter"><span style={{ width: `${v * 100}%` }} className={v >= 0.9 ? "comp" : v >= 0.6 ? "susp" : v >= 0.3 ? "watch" : "normal"} /><em>{v.toFixed(2)}</em></span>;
