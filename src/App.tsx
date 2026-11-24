import { useState } from "react";
import { runScenario } from "./demo/scenario";
import type { LogEntry } from "./demo/scenario";

export function App() {
  const [log, setLog] = useState<LogEntry[]>([]);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      setLog(await runScenario());
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 860, margin: "2rem auto", padding: "0 1rem" }}>
      <h1>BhūmiSign</h1>
      <p>Browser-only PKI for land titles. Everything below runs in your browser with the Web Crypto API.</p>
      <button onClick={run} disabled={busy}>
        {busy ? "Running…" : "Run full scenario"}
      </button>
      <table style={{ width: "100%", marginTop: "1rem", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <th align="left">Step</th>
            <th align="left">Expected</th>
            <th align="left">Outcome</th>
            <th align="left">Detail</th>
          </tr>
        </thead>
        <tbody>
          {log.map((row) => (
            <tr key={row.step} style={{ color: row.pass ? "inherit" : "crimson" }}>
              <td>{row.step}</td>
              <td>{row.expected}</td>
              <td>{row.outcome}</td>
              <td>{row.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
