"use client";

import { useState, useEffect } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Shield, Trash, AlertTriangle } from "lucide-react";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  const [credentials, setCredentials] = useState<any[]>([]); // {id, name, created_at, prf_enabled, is_primary, supports_sign_count}
  const [activity, setActivity] = useState<any[]>([]); // {time, ip, device_name, success}
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [anomalyWarning, setAnomalyWarning] = useState<string | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch credentials
      const credsResp = await fetch("/api/user/credentials/");
      if (!credsResp.ok) throw new Error("Failed to fetch credentials");
      const creds = await credsResp.json();
      setCredentials(creds);

      // Fetch activity logs
      const activityResp = await fetch("/api/user/activity/");
      if (!activityResp.ok) throw new Error("Failed to fetch activity");
      const logs = await activityResp.json();
      setActivity(logs);

      // Client-side anomaly check (logins after local last without this session)
      const localLast = localStorage.getItem('last_login_time');
      if (localLast) {
        const recentUnexplained = logs.filter((log: any) => new Date(log.time) > new Date(localLast) && !log.success); // Example: failed attempts after last
        if (recentUnexplained.length > 0) {
          setAnomalyWarning("Unusual activity detected! Review logs below and revoke suspicious devices.");
        }
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleAddSecondary = async (deviceName: string = "New Device") => {
    setError(null);
    try {
      // Step 1: Approve with primary
      const approveStart = await fetch("/api/webauthn/credential/add/approve/start/", { method: "POST" });
      if (!approveStart.ok) throw new Error("Approval start failed");
      const approveOptions = await approveStart.json();
      const approveCred = await startAuthentication(approveOptions);
      const approveFinish = await fetch("/api/webauthn/credential/add/approve/finish/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(approveCred),
      });
      if (!approveFinish.ok) throw new Error("Approval failed - possible clone detected?");

      // Step 2: Register secondary
      const addStart = await fetch("/api/webauthn/credential/add/start/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_name: deviceName }),
      });
      if (!addStart.ok) throw new Error("Add start failed");
      const addOptions = await addStart.json();
      const addCred = await startRegistration(addOptions);
      const addFinish = await fetch("/api/webauthn/credential/add/finish/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addCred),
      });
      if (!addFinish.ok) throw new Error("Add failed");

      alert("Secondary device added successfully!");
      fetchData(); // Refresh list
    } catch (err: any) {
      let errorMsg = err.message || "Add failed";
      if (errorMsg.includes("clone")) {
        errorMsg = "Possible cloned device during approval! Check activity logs.";
      }
      setError(errorMsg);
    }
  };

  const handleRemove = async (credId: string) => {
    if (confirm("Remove this device?")) {
      try {
        const resp = await fetch(`/api/credential/${credId}/delete/`, { method: "DELETE" });
        if (!resp.ok) throw new Error("Remove failed");
        fetchData();
      } catch (err) {
        setError((err as Error).message);
      }
    }
  };

  if (loading) return <Loader2 className="animate-spin" />;

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Settings</h1>
      {error && <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>}
      {anomalyWarning && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertDescription>{anomalyWarning}</AlertDescription></Alert>}

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
            {credentials.map(cred => (
              <TableRow key={cred.id}>
                <TableCell>{cred.name}</TableCell>
                <TableCell>{new Date(cred.created_at).toLocaleString()}</TableCell>
                <TableCell>{cred.prf_enabled ? "Yes" : "No"}</TableCell>
                <TableCell>{cred.is_primary ? "Yes" : "No"}</TableCell>
                <TableCell>{cred.supports_sign_count ? "Yes" : "No (Software Passkey)"}</TableCell>
                <TableCell>
                  {!cred.is_primary && <Button variant="destructive" size="sm" onClick={() => handleRemove(cred.id)}><Trash className="h-4 w-4" /></Button>}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <Button onClick={() => handleAddSecondary()} className="mt-4"><Shield className="mr-2 h-4 w-4" /> Add Secondary Device</Button>
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
