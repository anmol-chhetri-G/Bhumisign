import { useState } from "react";
import { runScenario } from "./demo/scenario";
import type { LogEntry } from "./demo/scenario";
import { utf8 } from "./crypto/bytes";
import type { Bytes } from "./crypto/bytes";
import { generateSigningKeyPair, signFile, verifyFile } from "./crypto/primitives";

const INITIAL_DOC = "Land Parcel KTM-W10-K1234 deed transfer consent";

export function App() {
  const [log, setLog] = useState<LogEntry[]>([]);
  const [busy, setBusy] = useState(false);

  // Interactive document / binary file signing state
  const [docText, setDocText] = useState(INITIAL_DOC);
  const [fileName, setFileName] = useState<string | null>(null);
  const [payloadBytes, setPayloadBytes] = useState<Bytes>(() => utf8(INITIAL_DOC));
  const [docSig, setDocSig] = useState("");
  const [docKey, setDocKey] = useState<CryptoKeyPair | null>(null);
  const [verifyStatus, setVerifyStatus] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    try {
      setLog(await runScenario());
    } finally {
      setBusy(false);
    }
  }

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    setFileName(file.name);
    setPayloadBytes(bytes);
    setDocSig("");
    setVerifyStatus(null);
  }

  function handleClearFile() {
    setFileName(null);
    setPayloadBytes(utf8(docText));
    setDocSig("");
    setVerifyStatus(null);
  }

  async function handleSignDoc() {
    const pair = docKey ?? (await generateSigningKeyPair(false));
    if (!docKey) setDocKey(pair);
    const sig = await signFile(pair.privateKey, payloadBytes);
    setDocSig(sig);
    setVerifyStatus(null);
  }

  async function handleVerifyDoc() {
    if (!docKey || !docSig) return;
    const valid = await verifyFile(docKey.publicKey, payloadBytes, docSig);
    setVerifyStatus(
      valid
        ? "Signature Valid: Document is authentic and integrity is verified."
        : "Signature Invalid: Document has been modified or signature is invalid.",
    );
  }

  function handleTamperByte() {
    const copy = new Uint8Array(payloadBytes);
    if (copy.length === 0) {
      setPayloadBytes(new Uint8Array([0x01]));
    } else {
      copy[0] = (copy[0] ?? 0) ^ 0x01;
      setPayloadBytes(copy);
    }
    setVerifyStatus(null);
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

      <hr style={{ margin: "2.5rem 0 1.5rem" }} />
      <h2>Interactive Document / File Signing</h2>
      <p>Sign arbitrary text or binary file bytes with ECDSA P-256 (non-extractable key) and verify integrity client-side.</p>
      <div style={{ marginBottom: "0.75rem", display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
        <label>
          <strong>Upload binary file (optional): </strong>
          <input type="file" onChange={handleFileSelect} />
        </label>
        {fileName && (
          <span>
            Active file: <code>{fileName}</code> ({payloadBytes.length} bytes){" "}
            <button type="button" onClick={handleClearFile}>Clear file</button>
          </span>
        )}
      </div>
      {!fileName && (
        <textarea
          value={docText}
          onChange={(e) => {
            setDocText(e.target.value);
            setPayloadBytes(utf8(e.target.value));
            setVerifyStatus(null);
          }}
          rows={3}
          style={{ width: "100%", padding: "0.5rem", fontFamily: "monospace", boxSizing: "border-box" }}
        />
      )}
      <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        <button onClick={handleSignDoc}>Sign {fileName ? "File" : "Document"}</button>
        <button onClick={handleVerifyDoc} disabled={!docSig}>
          Verify Signature
        </button>
        <button onClick={handleTamperByte} disabled={!docSig}>
          Simulate 1-Byte Tamper
        </button>
      </div>
      {docSig && (
        <div style={{ marginTop: "0.75rem", fontSize: "0.85rem", wordBreak: "break-all" }}>
          <strong>Signature (ECDSA 64-byte base64url):</strong> <code>{docSig}</code>
        </div>
      )}
      {verifyStatus && (
        <div
          style={{
            marginTop: "0.5rem",
            fontWeight: "bold",
            color: verifyStatus.startsWith("Signature Valid") ? "green" : "crimson",
          }}
        >
          {verifyStatus}
        </div>
      )}
    </main>
  );
}
