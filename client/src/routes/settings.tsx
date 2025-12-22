"use client";

import { useState, useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Shield, Trash, AlertTriangle } from "lucide-react";
import {
  startAuthentication,
  startRegistration,
  base64URLStringToBuffer,
} from "@simplewebauthn/browser";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  const [credentials, setCredentials] = useState<any[]>([]);
  const [activity, setActivity] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [anomalyWarning, setAnomalyWarning] = useState<string | null>(null);
  const [addCode, setAddCode] = useState<string | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch credentials (PRIMARY ONLY)
      const credsResp = await fetch("/api/webauthn/user/credentials/", {
        credentials: "include",
      });
      if (!credsResp.ok) {
        if (credsResp.status === 403)
          throw new Error("Access denied (primary device required).");
        if (credsResp.status === 401)
          throw new Error("Not authenticated. Please login again.");
        throw new Error("Failed to fetch credentials");
      }
      const creds = await credsResp.json();
      setCredentials(creds);

      // Fetch activity logs (PRIMARY ONLY)
      const activityResp = await fetch("/api/webauthn/user/activity/", {
        credentials: "include",
      });
      if (!activityResp.ok) {
        if (activityResp.status === 403)
          throw new Error("Access denied (primary device required).");
        if (activityResp.status === 401)
          throw new Error("Not authenticated. Please login again.");
        throw new Error("Failed to fetch activity");
      }
      const logs = await activityResp.json();
      setActivity(logs);

      // Client-side anomaly check (optional)
      const localLast = localStorage.getItem("last_login_time");
      if (localLast) {
        const recentUnexplained = logs.filter(
          (log: any) => new Date(log.time) > new Date(localLast) && !log.success
        );
        if (recentUnexplained.length > 0) {
          setAnomalyWarning(
            "Unusual activity detected! Review logs below and revoke suspicious devices."
          );
        } else {
          setAnomalyWarning(null);
        }
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateAddCode = async () => {
    if (
      !confirm(
        "To generate the add code, you will be prompted to confirm with your primary passkey. Continue?"
      )
    )
      return;

    setError(null);
    setAddCode(null);

    try {
      // 1) Start approval (PRIMARY ONLY)
      const approveStart = await fetch(
        "/api/webauthn/credential/add/approve/start/",
        { method: "POST", credentials: "include" }
      );

      if (!approveStart.ok) {
        if (approveStart.status === 403)
          throw new Error("Primary device required (403).");
        if (approveStart.status === 401)
          throw new Error("Not authenticated (401).");
        throw new Error("Approval start failed");
      }

      const approveOptions = await approveStart.json();

      // Convert PRF salts from base64url strings to ArrayBuffer
      const prfEval = approveOptions.extensions?.prf?.eval;
      if (prfEval) {
        prfEval.first = base64URLStringToBuffer(prfEval.first);
        if (prfEval.second) {
          prfEval.second = base64URLStringToBuffer(prfEval.second);
        }
      }

      // 2) WebAuthn prompt (get assertion from PRIMARY)
      const approveCred = await startAuthentication(approveOptions);

      // 3) Finish approval -> get add_code
      const approveFinish = await fetch(
        "/api/webauthn/credential/add/approve/finish/",
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(approveCred),
        }
      );

      if (!approveFinish.ok) {
        if (approveFinish.status === 403)
          throw new Error("Primary device required (403).");
        throw new Error("Approval failed - possible clone detected?");
      }

      const result = await approveFinish.json();
      setAddCode(result.add_code);
    } catch (err: any) {
      let errorMsg = err.message || "Failed to generate add code";
      if (errorMsg.includes("clone")) {
        errorMsg = "Possible cloned device during approval! Check activity logs.";
      }
      setError(errorMsg);
    }
  };

  const handleRemove = async (credId: string) => {
  if (!confirm("Remove this device? You will be prompted to confirm with your primary passkey.")) return;

  setError(null);

  try {
    // 1) Start delete approval (PRIMARY ONLY)
    const approveStart = await fetch("/api/webauthn/credential/delete/approve/start/", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_cred_id: credId }),
    });

    if (!approveStart.ok) {
      if (approveStart.status === 403) throw new Error("Primary device required (403).");
      if (approveStart.status === 401) throw new Error("Not authenticated (401).");
      throw new Error("Delete approval start failed");
    }

    const approveOptions = await approveStart.json();

    // Convert PRF salts to ArrayBuffer (same logic as generate add code)
    const prfEval = approveOptions.extensions?.prf?.eval;
    if (prfEval) {
      prfEval.first = base64URLStringToBuffer(prfEval.first);
      if (prfEval.second) prfEval.second = base64URLStringToBuffer(prfEval.second);
    }

    // 2) WebAuthn prompt (assertion from PRIMARY)
    const assertion = await startAuthentication(approveOptions);

    // 3) Finish approval -> actual deletion happens server-side
    const approveFinish = await fetch("/api/webauthn/credential/delete/approve/finish/", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(assertion),
    });

    if (!approveFinish.ok) {
      const txt = await approveFinish.text().catch(() => "");
      if (approveFinish.status === 403) throw new Error("Primary device required (403).");
      throw new Error(`Delete approval failed: ${txt || approveFinish.statusText}`);
    }

    // instant UI update + refetch
    setCredentials((curr) => curr.filter((c) => c.id !== credId));
    fetchData();
  } catch (err) {
    setError((err as Error).message);
  }
};


  // Optional test flow: approve + add in one UI (if your backend supports /add/start + /add/finish)
  const handleAddSecondary = async (deviceName: string = "New Device") => {
    setError(null);

    try {
      // Step 1: Approve with primary
      const approveStart = await fetch(
        "/api/webauthn/credential/add/approve/start/",
        { method: "POST", credentials: "include" }
      );

      if (!approveStart.ok) {
        if (approveStart.status === 403)
          throw new Error("Primary device required (403).");
        if (approveStart.status === 401)
          throw new Error("Not authenticated (401).");
        throw new Error("Approval start failed");
      }

      const approveOptions = await approveStart.json();

      // Convert PRF salts
      const prfEval = approveOptions.extensions?.prf?.eval;
      if (prfEval) {
        prfEval.first = base64URLStringToBuffer(prfEval.first);
        if (prfEval.second) {
          prfEval.second = base64URLStringToBuffer(prfEval.second);
        }
      }

      const approveCred = await startAuthentication(approveOptions);

      const approveFinish = await fetch(
        "/api/webauthn/credential/add/approve/finish/",
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(approveCred),
        }
      );

      if (!approveFinish.ok) {
        if (approveFinish.status === 403)
          throw new Error("Primary device required (403).");
        throw new Error("Approval failed - possible clone detected?");
      }

      // Step 2: Start secondary registration (depends on your backend)
      const addStart = await fetch("/api/webauthn/credential/add/start/", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_name: deviceName }),
      });

      if (!addStart.ok) {
        if (addStart.status === 403)
          throw new Error("Primary device required (403).");
        throw new Error("Add start failed");
      }

      const addOptions = await addStart.json();
      const addCred = await startRegistration(addOptions);

      const addFinish = await fetch("/api/webauthn/credential/add/finish/", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addCred),
      });

      if (!addFinish.ok) throw new Error("Add failed");

      alert("Secondary device added successfully!");
      fetchData();
    } catch (err: any) {
      let errorMsg = err.message || "Add failed";
      if (errorMsg.includes("clone")) {
        errorMsg = "Possible cloned device during approval! Check activity logs.";
      }
      setError(errorMsg);
    }
  };

  if (loading)
    return (
      <div className="p-8 flex items-center gap-2 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        Loading…
      </div>
    );

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Settings</h1>

      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {anomalyWarning && (
        <Alert variant="destructive" className="mb-4">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{anomalyWarning}</AlertDescription>
        </Alert>
      )}

      <section className="mb-8">
        <h2 className="text-xl mb-2">Devices</h2>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>PRF</TableHead>
              <TableHead>Primary</TableHead>
              <TableHead>Sign Count Support</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>

          <TableBody>
            {credentials.map((cred) => (
              <TableRow key={cred.id}>
                <TableCell>{cred.name}</TableCell>
                <TableCell>{new Date(cred.created_at).toLocaleString()}</TableCell>
                <TableCell>{cred.prf_enabled ? "Yes" : "No"}</TableCell>
                <TableCell>{cred.is_primary ? "Yes" : "No"}</TableCell>
                <TableCell>
                  {cred.supports_sign_count ? "Yes" : "No (Software Passkey)"}
                </TableCell>
                <TableCell>
                  {cred.is_primary ? (
                  <span className="text-muted-foreground">-</span>
                  ) : (
                    <Button
                      type="button"
                      className="text-red-600 hover:text-red-700 hover:bg-red-50 rounded px-2 py-1"
                      onClick={() => handleRemove(cred.id)}
                    >
                      delete
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>

        <Button onClick={handleGenerateAddCode} className="mt-4">
          <Shield className="mr-2 h-4 w-4" />
          Generate Add Code for Secondary Device
        </Button>

        {addCode && (
          <Alert className="mt-4">
            <AlertDescription>
              Add Code: {addCode} (expires in 10 minutes). Enter on the new
              device.
            </AlertDescription>
          </Alert>
        )}

        {/* Si tu veux tester l’ajout complet depuis le même appareil (pas réaliste mais utile en dev) */}
        {/* <Button onClick={() => handleAddSecondary("My Secondary Device")} className="mt-4 ml-2">
          Add Secondary (test)
        </Button> */}
      </section>

      <section>
        <h2 className="text-xl mb-2">Recent Activity</h2>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>Success</TableHead>
            </TableRow>
          </TableHeader>

          <TableBody>
            {activity.map((log, i) => (
              <TableRow key={i}>
                <TableCell>{new Date(log.time).toLocaleString()}</TableCell>
                <TableCell>{log.ip}</TableCell>
                <TableCell>{log.device_name}</TableCell>
                <TableCell>{log.success ? "Yes" : "No"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>
    </div>
  );
}
