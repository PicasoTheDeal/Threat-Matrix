/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect, useRef, useCallback } from "react";
import "bootstrap-icons/font/bootstrap-icons.css";
import "./App.css";

declare global {
  interface Window {
    turnstile: {
      render: (selector: string, options: any) => string;
      execute: (widgetId: string, options?: any) => void;
      reset: (widgetId: string) => void;
      getResponse: (widgetId: string) => string;
    };
  }
}

const THEME = {
  bg: "#0f0f0f",
  surface: "#0a0a0a",
  border: "#1c2333",
  borderSubtle: "#161d28",
  text: "#e6edf3",
  textSecondary: "#b1bac4",
  textTertiary: "#8b949e",
  accent: "#5b7a9e",
  accentHover: "#3d5068",
  font: "'JetBrains Mono', 'SF Mono', 'Cascadia Code', 'Consolas', monospace",
};

const TOPIC_DATABASE: Record<string, string[]> = {
  "Web Frameworks & Libs": ["React", "Vue", "Angular", "Svelte", "Laravel", "Django", "Flask", "Spring", "Next.js", "Nuxt", "Vite", "Express", "Ruby on Rails", "ASP.NET", "jQuery", "NPM"],
  "Attack Vectors & Threats": ["Zero-Day", "Malware", "Phishing", "Ransomware", "RAT", "DDoS", "SQL Injection", "XSS", "CSRF", "Buffer Overflow", "Man-in-the-Middle", "Privilege Escalation", "Supply Chain Attack"],
  "Software & Platforms": ["Google Workspace", "Telegram", "WhatsApp", "Discord", "Slack", "Microsoft 365", "Zoom", "AWS", "Azure", "Cloudflare", "Docker", "Kubernetes", "GitLab", "GitHub", "Oracle", "SAP"],
  "Operating Systems": ["Linux", "Windows", "macOS", "Android", "iOS", "FreeBSD", "Ubuntu", "Debian", "Arch Linux", "Kali Linux", "RedHat", "CentOS"],
  "Networking & Hardware": ["Cisco", "Juniper", "Fortinet", "Palo Alto", "Ubiquiti", "NVIDIA", "Intel", "AMD", "Broadcom"]
};

const CACHE_KEY = "matrix_logs_cache";

interface ThreatLog {
  id: string;
  title: string;
  excerpt: string;
  category: string;
  date: string;
  readTime: number;
  source: string;
  url: string;
  impact?: string;
}

interface InteractionData {
  likes: number;
  liked: boolean;
  comments: { id: number; content: string; created_at: string; user_id: number; username: string }[];
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8787";
const TURNSTILE_SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY;

export default function App() {
  const [logs, setLogs] = useState<ThreatLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [token, setToken] = useState<string | null>(() => localStorage.getItem("matrix_auth_token"));
  const isAuthenticated = !!token;

  const [showConfigMatrix, setShowConfigMatrix] = useState<boolean>(false);
  const [modalStage, setModalStage] = useState<"login" | "signup" | "profile">("login");

  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [copiedNotification, setCopiedNotification] = useState<boolean>(false);

  const [userProfileTags, setUserProfileTags] = useState<string[]>([]);
  const [initialTagsLoaded, setInitialTagsLoaded] = useState<boolean>(false);

  const [configSearch, setConfigSearch] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [selectedTopic, setSelectedTopic] = useState<string>("");
  const [selectedSource, setSelectedSource] = useState<string>("");
  const [startDate, setStartDate] = useState<string>("");

  const [activeFeedTab, setActiveFeedTab] = useState<"cluster" | "selective">("cluster");

  const [interactions, setInteractions] = useState<Record<string, InteractionData>>({});
  const [commentInputs, setCommentInputs] = useState<Record<string, string>>({});
  const [editingComment, setEditingComment] = useState<{ logId: string; commentId: number; content: string } | null>(null);

  const [turnstileLoaded, setTurnstileLoaded] = useState(false);
  
  const invisibleWidgetId = useRef<string | null>(null);
  const loginWidgetId = useRef<string | null>(null);
  const signupWidgetId = useRef<string | null>(null);
  const pendingInvisibleResolve = useRef<((token: string) => void) | null>(null);

  useEffect(() => {
    if (!document.querySelector('link[href*="JetBrains+Mono"]')) {
      const link = document.createElement("link");
      link.href = "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap";
      link.rel = "stylesheet";
      document.head.appendChild(link);
    }
  }, []);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = `
      html, body {
        background-color: #0f0f0f !important;
        margin: 0;
        padding: 0;
        width: 100%;
        min-height: 100vh;
      }
      #root {
        background-color: transparent !important;
        width: 100%;
        display: flex;
        justify-content: center;
        align-items: flex-start;
        min-height: 100vh;
      }
    `;
    document.head.appendChild(style);
    return () => {
      document.head.removeChild(style);
    };
  }, []);

  useEffect(() => {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.onload = () => setTurnstileLoaded(true);
    document.head.appendChild(script);
    return () => {
      document.head.removeChild(script);
    };
  }, []);

  useEffect(() => {
    if (turnstileLoaded && window.turnstile) {
      const container = document.getElementById("turnstile-invisible-container");
      if (container && !invisibleWidgetId.current) {
        invisibleWidgetId.current = window.turnstile.render("#turnstile-invisible-container", {
          sitekey: TURNSTILE_SITE_KEY,
          size: "invisible",
          callback: (tkn: string) => {
            if (pendingInvisibleResolve.current) {
              pendingInvisibleResolve.current(tkn);
              pendingInvisibleResolve.current = null;
            }
            window.turnstile.reset(invisibleWidgetId.current!);
          },
        });
      }
    }
  }, [turnstileLoaded]);

  useEffect(() => {
    if (turnstileLoaded && window.turnstile && modalStage === "login" && showConfigMatrix) {
      const container = document.getElementById("login-turnstile");
      if (container && !loginWidgetId.current) {
        loginWidgetId.current = window.turnstile.render("#login-turnstile", {
          sitekey: TURNSTILE_SITE_KEY,
          size: "normal",
          callback: () => {},
        });
      }
    }
    return () => {
      if (loginWidgetId.current && window.turnstile) {
        window.turnstile.reset(loginWidgetId.current);
        loginWidgetId.current = null;
      }
    };
  }, [turnstileLoaded, modalStage, showConfigMatrix]);

  useEffect(() => {
    if (turnstileLoaded && window.turnstile && modalStage === "signup" && showConfigMatrix) {
      const container = document.getElementById("signup-turnstile");
      if (container && !signupWidgetId.current) {
        signupWidgetId.current = window.turnstile.render("#signup-turnstile", {
          sitekey: TURNSTILE_SITE_KEY,
          size: "normal",
          callback: () => {},
        });
      }
    }
    return () => {
      if (signupWidgetId.current && window.turnstile) {
        window.turnstile.reset(signupWidgetId.current);
        signupWidgetId.current = null;
      }
    };
  }, [turnstileLoaded, modalStage, showConfigMatrix]);

  const getInvisibleTurnstileToken = useCallback(async (): Promise<string> => {
    if (!window.turnstile || !invisibleWidgetId.current) {
      throw new Error("Turnstile not loaded");
    }
    if (pendingInvisibleResolve.current) {
      throw new Error("Turnstile verification already in progress");
    }
    return new Promise((resolve, reject) => {
      pendingInvisibleResolve.current = resolve;
      window.turnstile.execute(invisibleWidgetId.current!);
      setTimeout(() => {
        if (pendingInvisibleResolve.current) {
          pendingInvisibleResolve.current = null;
          reject(new Error("Turnstile verification timed out"));
        }
      }, 30000);
    });
  }, []);

  useEffect(() => {
    if (token && !initialTagsLoaded) {
      fetchUserParameters(token);
    }
  }, [token, initialTagsLoaded]);

  const fetchUserParameters = async (authToken: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/parameters`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUserProfileTags(data.tags || []);
      }
    } catch (e) {}
    setInitialTagsLoaded(true);
  };

  const syncUserParameters = async (newTags: string[]) => {
    if (!token) return;
    try {
      await fetch(`${API_BASE}/api/parameters`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ tags: newTags })
      });
    } catch (e) {}
  };

  const handleSanitizedUsernameChange = (val: string) => {
    const cleanValue = val.replace(/[^a-zA-Z0-9_.-]/g, "");
    setUsername(cleanValue);
  };

  useEffect(() => {
    if (!isAuthenticated) setActiveFeedTab("cluster");
  }, [isAuthenticated]);

  const policyCheck = {
    length: password.length >= 128,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    digit: /[0-9]/.test(password),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
  };
  const isFormCompliant = Object.values(policyCheck).every(Boolean);

  useEffect(() => {
    let cancelled = false;
    const cached = localStorage.getItem(CACHE_KEY);
    const existingLogs: ThreatLog[] = cached ? JSON.parse(cached) : [];

    if (!cancelled && existingLogs.length > 0) {
      setLogs(existingLogs);
      setLoading(false);
    }

    const fetchAndMerge = async () => {
      try {
        const headers: Record<string, string> = {};
        if (token) {
          headers["Authorization"] = `Bearer ${token}`;
        }

        const res = await fetch(`${API_BASE}/api/logs`, { headers });

        if (res.status === 401) {
          handleDisconnect();
          throw new Error("Operational tracking token authorization certificate rejected.");
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        if (!res.ok) {
          const errorData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
          throw new Error(errorData.error || `Pipeline failed with status ${res.status}`);
        }

        const freshLogs: ThreatLog[] = await res.json();

        if (cancelled) return;

        const map = new Map<string, ThreatLog>();
        existingLogs.forEach((log) => map.set(log.id, log));
        freshLogs.forEach((log) => map.set(log.id, log));

        const merged = Array.from(map.values()).sort((a, b) => {
          const dateA = Date.parse(a.date);
          const dateB = Date.parse(b.date);
          if (isNaN(dateA) && isNaN(dateB)) return 0;
          if (isNaN(dateA)) return 1;
          if (isNaN(dateB)) return -1;
          return dateB - dateA;
        });

        if (!cancelled) {
          setLogs(merged);
          localStorage.setItem(CACHE_KEY, JSON.stringify(merged));
          setError(null);
        }
      } catch (err: any) {
        if (!cancelled) {
          if (existingLogs.length === 0) setLogs([]);
          setError(err.message || "Pipeline sync error.");
          console.error("DEBUG:", err);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchAndMerge();
    return () => { cancelled = true; };
  }, [token]);

  useEffect(() => {
    const logIds = logs.map(log => log.id);
    if (logIds.length === 0) return;
    const batchSize = 50;
    const fetchBatch = async () => {
      for (let i = 0; i < logIds.length; i += batchSize) {
        const batch = logIds.slice(i, i + batchSize);
        const idsParam = batch.join(",");
        try {
          const headers: Record<string, string> = {};
          if (token) headers["Authorization"] = `Bearer ${token}`;
          const res = await fetch(`${API_BASE}/api/interact?log_ids=${encodeURIComponent(idsParam)}`, { headers });
          if (res.ok) {
            const data = await res.json();
            setInteractions(prev => ({ ...prev, ...data }));
          }
        } catch (e) {}
      }
    };
    fetchBatch();
  }, [logs.length]);

  const handleLikeToggle = async (logId: string) => {
    if (!token) return;
    const current = interactions[logId] || { likes: 0, liked: false, comments: [] };
    const newLiked = !current.liked;
    setInteractions(prev => ({
      ...prev,
      [logId]: {
        ...prev[logId] || { likes: 0, liked: false, comments: [] },
        likes: newLiked ? (prev[logId]?.likes || 0) + 1 : Math.max(0, (prev[logId]?.likes || 0) - 1),
        liked: newLiked
      }
    }));

    try {
      const action = newLiked ? "like" : "unlike";
      const res = await fetch(`${API_BASE}/api/interact`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ action, log_id: logId })
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      if (data.interaction) {
        setInteractions(prev => ({ ...prev, [logId]: data.interaction }));
      }
    } catch (e) {
      setInteractions(prev => ({
        ...prev,
        [logId]: current
      }));
    }
  };

  const handleCommentSubmit = async (logId: string) => {
    if (!token) return;
    const content = commentInputs[logId]?.trim();
    if (!content) return;

    let turnstileToken = "";
    try {
      turnstileToken = await getInvisibleTurnstileToken();
    } catch (err) {
      alert("Turnstile verification failed. Please try again.");
      return;
    }

    const tempComment = {
      id: Date.now(),
      content,
      created_at: new Date().toISOString(),
      user_id: 0,
      username: username || "you"
    };
    const currentComments = interactions[logId]?.comments || [];
    setInteractions(prev => ({
      ...prev,
      [logId]: {
        ...prev[logId] || { likes: 0, liked: false, comments: [] },
        comments: [...(prev[logId]?.comments || []), tempComment]
      }
    }));
    setCommentInputs(prev => ({ ...prev, [logId]: "" }));

    try {
      const res = await fetch(`${API_BASE}/api/interact`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ action: "comment", log_id: logId, content, turnstileToken })
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      if (data.interaction) {
        setInteractions(prev => ({ ...prev, [logId]: data.interaction }));
      }
    } catch (e) {
      setInteractions(prev => ({
        ...prev,
        [logId]: { ...prev[logId] || { likes: 0, liked: false, comments: [] }, comments: currentComments }
      }));
    }
  };

  const handleEditComment = async (logId: string, commentId: number, newContent: string) => {
    if (!token || !newContent.trim()) return;
    const currentComments = interactions[logId]?.comments || [];
    setInteractions(prev => ({
      ...prev,
      [logId]: {
        ...prev[logId] || { likes: 0, liked: false, comments: [] },
        comments: prev[logId]?.comments.map(c => c.id === commentId ? { ...c, content: newContent.trim() } : c) || []
      }
    }));
    setEditingComment(null);

    try {
      const res = await fetch(`${API_BASE}/api/interact`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ action: "edit_comment", log_id: logId, comment_id: commentId, content: newContent.trim() })
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      if (data.interaction) {
        setInteractions(prev => ({ ...prev, [logId]: data.interaction }));
      }
    } catch (e) {
      setInteractions(prev => ({
        ...prev,
        [logId]: { ...prev[logId] || { likes: 0, liked: false, comments: [] }, comments: currentComments }
      }));
    }
  };

  const handleDeleteComment = async (logId: string, commentId: number) => {
    if (!token) return;
    const currentComments = interactions[logId]?.comments || [];
    setInteractions(prev => ({
      ...prev,
      [logId]: {
        ...prev[logId] || { likes: 0, liked: false, comments: [] },
        comments: prev[logId]?.comments.filter(c => c.id !== commentId) || []
      }
    }));

    try {
      const res = await fetch(`${API_BASE}/api/interact`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ action: "delete_comment", log_id: logId, comment_id: commentId })
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      if (data.interaction) {
        setInteractions(prev => ({ ...prev, [logId]: data.interaction }));
      }
    } catch (e) {
      setInteractions(prev => ({
        ...prev,
        [logId]: { ...prev[logId] || { likes: 0, liked: false, comments: [] }, comments: currentComments }
      }));
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    let turnstileToken = "";
    if (loginWidgetId.current && window.turnstile) {
      turnstileToken = window.turnstile.getResponse(loginWidgetId.current);
    }
    if (!turnstileToken) {
      setAuthError("Please complete the Turnstile verification.");
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, turnstileToken })
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Authentication rejection response from target core.");
      }

      localStorage.setItem("matrix_auth_token", data.token);
      setToken(data.token);
      setInitialTagsLoaded(false);
      setModalStage("profile");
    } catch (err: any) {
      setAuthError(err.message || "Failed to route confirmation packets to the authentication gateway.");
    }
  };

  const handleSignupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    if (!isFormCompliant) {
      setAuthError("Credential complexity criteria failure. Registration Denied.");
      return;
    }

    let turnstileToken = "";
    if (signupWidgetId.current && window.turnstile) {
      turnstileToken = window.turnstile.getResponse(signupWidgetId.current);
    }
    if (!turnstileToken) {
      setAuthError("Please complete the Turnstile verification.");
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, turnstileToken })
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Core registry pipeline rejection.");
      }

      localStorage.setItem("matrix_auth_token", data.token);
      setToken(data.token);
      setInitialTagsLoaded(false);
      setModalStage("profile");
    } catch (err: any) {
      setAuthError(err.message || "Registry frame generation link failure.");
    }
  };

  const handleDisconnect = () => {
    localStorage.removeItem("matrix_auth_token");
    localStorage.removeItem(CACHE_KEY);
    setToken(null);
    setUserProfileTags([]);
    setLogs([]);
    setUsername("");
    setPassword("");
    setModalStage("login");
  };

  const handleCopyCurrentPassword = () => {
    if (!password) return;
    navigator.clipboard.writeText(password).then(() => {
      setCopiedNotification(true);
      setTimeout(() => setCopiedNotification(false), 2000);
    });
  };

  const toggleTag = (tag: string) => {
    const formatted = tag.trim().toUpperCase();
    setUserProfileTags((prev) => {
      const newTags = prev.includes(formatted) ? prev.filter((t) => t !== formatted) : [...prev, formatted];
      syncUserParameters(newTags);
      return newTags;
    });
    setConfigSearch("");
  };

  const isSearchCustom =
    configSearch.trim() !== "" &&
    !Object.values(TOPIC_DATABASE).flat().some((t) => t.toLowerCase() === configSearch.toLowerCase());

  const filteredLogs = logs.filter((log) => {
    try {
      const matchesSearch =
        (log.title || "").toLowerCase().includes(search.toLowerCase()) ||
        (log.id || "").toLowerCase().includes(search.toLowerCase()) ||
        (log.excerpt || "").toLowerCase().includes(search.toLowerCase());

      const matchesTopic = selectedTopic
        ? (log.title + " " + log.excerpt + " " + log.category).toLowerCase().includes(selectedTopic.toLowerCase())
        : true;

      const matchesSource = selectedSource
        ? (log.source || "").toLowerCase().includes(selectedSource.toLowerCase())
        : true;

      const logTime = new Date(log.date).getTime();
      const matchesStart = startDate ? logTime >= new Date(startDate).getTime() : true;

      return matchesSearch && matchesTopic && matchesSource && matchesStart;
    } catch {
      return false;
    }
  });

  const profileFilteredLogs = filteredLogs.filter((log) => {
    try {
      if (userProfileTags.length === 0) return false;
      return userProfileTags.some(
        (tag) =>
          (log.category || "").toLowerCase().includes(tag.toLowerCase()) ||
          (log.title || "").toLowerCase().includes(tag.toLowerCase()) ||
          (log.excerpt || "").toLowerCase().includes(tag.toLowerCase())
      );
    } catch {
      return false;
    }
  });

  const allTags = Object.values(TOPIC_DATABASE).flat();

  const getImpactColor = (impact: string | undefined) => {
    if (impact === "CRITICAL") return "#f85149";
    if (impact === "HIGH") return "#f0883e";
    return THEME.accent;
  };

  const renderCard = (log: ThreatLog) => {
    const inter = interactions[log.id] || { likes: 0, liked: false, comments: [] };
    return (
      <article
        className="threat-card"
        key={log.id}
        style={{
          borderLeft: `4px solid ${getImpactColor(log.impact)}`,
          background: THEME.surface,
          padding: "15px",
          marginBottom: "15px",
          borderRadius: "4px",
          border: `1px solid ${THEME.border}`,
        }}
      >
        <div className="card-header">
          <span className="cve-id" style={{ color: THEME.accent, fontFamily: THEME.font }}>
            {log.id}
            {log.impact && (
              <span
                style={{
                  marginLeft: "10px",
                  fontSize: "0.7rem",
                  color: getImpactColor(log.impact),
                  border: `1px solid ${getImpactColor(log.impact)}`,
                  padding: "2px 6px",
                  borderRadius: "4px",
                }}
              >
                {log.impact}
              </span>
            )}
          </span>
        </div>
        <h2 className="card-title" style={{ margin: "10px 0" }}>
          <a
            href={log.url}
            target="_blank"
            rel="noreferrer"
            style={{
              color: THEME.text,
              textDecoration: "none",
              fontSize: "1.2rem",
              fontFamily: THEME.font,
            }}
          >
            {log.title}
          </a>
        </h2>
        <p className="card-excerpt" style={{ color: THEME.textSecondary, fontSize: "0.9rem", fontFamily: THEME.font }}>
          {log.excerpt}
        </p>

        <div
          className="card-footer"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "10px",
            marginTop: "15px",
            borderTop: `1px solid ${THEME.border}`,
            paddingTop: "10px",
          }}
        >
          <span
            className="category-tag"
            style={{
              background: "#161d28",
              padding: "2px 8px",
              borderRadius: "4px",
              fontSize: "0.8rem",
              color: THEME.textSecondary,
              fontFamily: THEME.font,
            }}
          >
            {log.category}
          </span>

          {log.id.startsWith("CVE") && (
            <div style={{ display: "flex", gap: "8px", fontSize: "0.8rem" }}>
              <a
                href={`https://www.google.com/search?q=${log.id}+exploit`}
                target="_blank"
                rel="noreferrer"
                style={{ color: THEME.textTertiary, textDecoration: "none" }}
                title="Search Google for Exploits"
              >
                <i className="bi bi-google"></i>
              </a>
              <a
                href={`https://github.com/search?q=${log.id}&type=repositories`}
                target="_blank"
                rel="noreferrer"
                style={{ color: THEME.textTertiary, textDecoration: "none" }}
                title="Search GitHub for PoCs"
              >
                <i className="bi bi-github"></i>
              </a>
            </div>
          )}

          <div style={{ display: "flex", gap: "15px", alignItems: "center", fontSize: "0.8rem", color: THEME.textTertiary, fontFamily: THEME.font }}>
            <a href={log.url} target="_blank" rel="noreferrer" style={{ color: THEME.accent, textDecoration: "none" }}>
              SRC: {log.source} ↗
            </a>
            <span>{log.date}</span>
          </div>
        </div>

        {isAuthenticated && (
          <div style={{ marginTop: "10px", borderTop: `1px solid ${THEME.border}`, paddingTop: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "15px", marginBottom: "8px" }}>
              <span
                onClick={() => handleLikeToggle(log.id)}
                style={{
                  cursor: "pointer",
                  color: inter.liked ? "#f85149" : THEME.textTertiary,
                  fontFamily: THEME.font,
                  fontSize: "0.8rem",
                  userSelect: "none",
                }}
              >
                <i className={`bi ${inter.liked ? "bi-heart-fill" : "bi-heart"}`}></i> {inter.likes}
              </span>
              <span
                style={{
                  cursor: "pointer",
                  color: THEME.textTertiary,
                  fontFamily: THEME.font,
                  fontSize: "0.8rem",
                }}
              >
                <i className="bi bi-chat"></i> {inter.comments.length}
              </span>
            </div>

            <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
              <input
                type="text"
                placeholder="Add a comment..."
                value={commentInputs[log.id] || ""}
                onChange={(e) => setCommentInputs(prev => ({ ...prev, [log.id]: e.target.value }))}
                onKeyDown={(e) => e.key === "Enter" && handleCommentSubmit(log.id)}
                style={{
                  flex: 1,
                  padding: "6px 10px",
                  background: "#0d0d0d",
                  border: `1px solid ${THEME.border}`,
                  color: THEME.text,
                  fontFamily: THEME.font,
                  fontSize: "0.8rem",
                  borderRadius: "4px",
                }}
              />
              <button
                type="button"
                onClick={() => handleCommentSubmit(log.id)}
                style={{
                  background: THEME.accent,
                  color: THEME.text,
                  border: "none",
                  padding: "6px 12px",
                  cursor: "pointer",
                  fontFamily: THEME.font,
                  fontSize: "0.8rem",
                  borderRadius: "4px",
                }}
              >
                SEND
              </button>
            </div>

            {inter.comments.length > 0 && (
              <div style={{ maxHeight: "150px", overflowY: "auto", borderTop: `1px solid ${THEME.border}`, paddingTop: "5px" }}>
                {[...inter.comments].reverse().map((comment) => (
                  <div key={comment.id} style={{ marginBottom: "6px", fontSize: "0.8rem", display: "flex", alignItems: "flex-start", gap: "5px" }}>
                    <div style={{ flex: 1 }}>
                      <span style={{ color: THEME.accent, fontFamily: THEME.font }}>{comment.username}:</span>{" "}
                      <span style={{ color: THEME.textSecondary }}>{comment.content}</span>
                    </div>
                    {isAuthenticated && (
                      <div style={{ display: "flex", gap: "4px" }}>
                        <span
                          onClick={() => setEditingComment({ logId: log.id, commentId: comment.id, content: comment.content })}
                          style={{ cursor: "pointer", color: THEME.textTertiary, textDecoration: "underline", fontSize: "0.7rem" }}
                          title="Edit"
                        >
                          <i className="bi bi-pencil"></i>
                        </span>
                        <span
                          onClick={() => handleDeleteComment(log.id, comment.id)}
                          style={{ cursor: "pointer", color: "#f85149", fontSize: "0.7rem" }}
                          title="Delete"
                        >
                          <i className="bi bi-trash"></i>
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {editingComment && editingComment.logId === log.id && (
              <div style={{ display: "flex", gap: "8px", marginTop: "5px" }}>
                <input
                  type="text"
                  value={editingComment.content}
                  onChange={(e) => setEditingComment(prev => prev ? { ...prev, content: e.target.value } : null)}
                  style={{
                    flex: 1,
                    padding: "4px 8px",
                    background: "#0d0d0d",
                    border: `1px solid ${THEME.accent}`,
                    color: THEME.text,
                    fontFamily: THEME.font,
                    fontSize: "0.8rem",
                    borderRadius: "4px",
                  }}
                />
                <button
                  type="button"
                  onClick={() => handleEditComment(log.id, editingComment.commentId, editingComment.content)}
                  style={{
                    background: THEME.accent,
                    color: THEME.text,
                    border: "none",
                    padding: "4px 8px",
                    cursor: "pointer",
                    fontFamily: THEME.font,
                    fontSize: "0.8rem",
                    borderRadius: "4px",
                  }}
                >
                  SAVE
                </button>
                <button
                  type="button"
                  onClick={() => setEditingComment(null)}
                  style={{
                    background: "transparent",
                    color: THEME.textTertiary,
                    border: `1px solid ${THEME.border}`,
                    padding: "4px 8px",
                    cursor: "pointer",
                    fontFamily: THEME.font,
                    fontSize: "0.8rem",
                    borderRadius: "4px",
                  }}
                >
                  CANCEL
                </button>
              </div>
            )}
          </div>
        )}
      </article>
    );
  };

  const clearCacheAndReload = () => {
    localStorage.removeItem(CACHE_KEY);
    window.location.reload();
  };

  useEffect(() => {
    if (window.innerWidth <= 1100) return;

    const canvas = document.createElement("canvas");
    canvas.id = "web-line-background";
    canvas.style.cssText =
      "position:fixed; top:0; left:0; width:100%; height:100%; z-index:0; pointer-events:none;";
    document.body.appendChild(canvas);

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const DOT_RADIUS = 1.2;
    const BASE_ALPHA = 0.22;
    const MOUSE_RADIUS = 180;
    const MAX_OFFSET = 12;
    const SCROLL_WAVE_AMP = 3;
    const SCROLL_FREQ = 0.005;
    const GRID_WAVE_FREQ = 0.02;
    const WHITISH_COLOR = "255, 255, 255";

    const WEB_LINE_COLOR = `rgba(${WHITISH_COLOR}, 0.20)`;
    const WEB_LINE_WIDTH = 1.0;

    const CUBE_COUNT = 11;
    const CUBE_SIZE = 42;
    const CUBE_DISTANCE = 400;
    const FOCAL_LENGTH = 400;
    const CUBE_LINE_COLOR = `rgba(${WHITISH_COLOR}, 0.10)`;
    const CUBE_LINE_WIDTH = 1.0;

    let dots: any[] = [];
    let mouseX = -1000, mouseY = -1000;
    let scrollY = window.scrollY;
    let width: number, height: number;
    let cubes: any[] = [];
    let animationFrameId: number;

    const half = CUBE_SIZE / 2;
    const cubeVertices = [
      [-half, -half, -half], [half, -half, -half],
      [half, half, -half], [-half, half, -half],
      [-half, -half, half], [half, -half, half],
      [half, half, half], [-half, half, half],
    ];
    const cubeEdges = [
      [0, 1], [1, 2], [2, 3], [3, 0],
      [4, 5], [5, 6], [6, 7], [7, 4],
      [0, 4], [1, 5], [2, 6], [3, 7],
    ];

    const densityFactor = 8500;

    function resize() {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width;
      canvas.height = height;

      const totalDots = Math.floor((width * height) / densityFactor);
      dots = [];
      for (let i = 0; i < totalDots; i++) {
        dots.push({
          baseX: Math.random() * width,
          baseY: Math.random() * height,
          offsetX: 0,
          offsetY: 0,
        });
      }

      if (cubes.length === 0) {
        const scale = FOCAL_LENGTH / (FOCAL_LENGTH + CUBE_DISTANCE);
        for (let i = 0; i < CUBE_COUNT; i++) {
          const maxWorldX = (width / 2 + CUBE_SIZE) / scale;
          const maxWorldY = (height / 2 + CUBE_SIZE) / scale;
          cubes.push({
            cx: (Math.random() * 2 - 1) * maxWorldX * 0.8,
            cy: (Math.random() * 2 - 1) * maxWorldY * 0.8,
            cz: CUBE_DISTANCE,
            vx: (Math.random() - 0.5) * 0.5,
            vy: (Math.random() - 0.5) * 0.5,
            rotX: Math.random() * Math.PI * 2,
            rotY: Math.random() * Math.PI * 2,
            rotZ: Math.random() * Math.PI * 2,
            rotSpeedX: (Math.random() - 0.5) * 0.006,
            rotSpeedY: (Math.random() - 0.5) * 0.006,
            rotSpeedZ: (Math.random() - 0.5) * 0.003,
          });
        }
      }
    }

    function rotatePoint(x: number, y: number, z: number, rotX: number, rotY: number, rotZ: number) {
      let cos = Math.cos(rotX), sin = Math.sin(rotX);
      let y1 = y * cos - z * sin;
      let z1 = y * sin + z * cos;
      cos = Math.cos(rotY); sin = Math.sin(rotY);
      let x2 = x * cos + z1 * sin;
      let z2 = -x * sin + z1 * cos;
      cos = Math.cos(rotZ); sin = Math.sin(rotZ);
      let x3 = x2 * cos - y1 * sin;
      let y3 = x2 * sin + y1 * cos;
      return { x: x3, y: y3, z: z2 };
    }

    function project(x: number, y: number, z: number) {
      const scale = FOCAL_LENGTH / (FOCAL_LENGTH + z);
      return { sx: width / 2 + x * scale, sy: height / 2 + y * scale };
    }

    function animate() {
      if (!ctx) return;
      ctx.clearRect(0, 0, width, height);

      const scrollOffset = scrollY;
      for (let dot of dots) {
        const dx = dot.baseX - mouseX;
        const dy = dot.baseY - mouseY;
        const dist = Math.sqrt(dx * dx + dy * dy);

        let targetOffX = 0, targetOffY = 0;
        let mouseAlphaBoost = 0;
        if (dist < MOUSE_RADIUS && dist > 0) {
          const factor = 1 - dist / MOUSE_RADIUS;
          const angle = Math.atan2(dy, dx);
          targetOffX = Math.cos(angle) * factor * MAX_OFFSET;
          targetOffY = Math.sin(angle) * factor * MAX_OFFSET;
          mouseAlphaBoost = factor * 0.25;
        }

        dot.offsetX += (targetOffX - dot.offsetX) * 0.12;
        dot.offsetY += (targetOffY - dot.offsetY) * 0.12;

        const waveX = Math.sin(dot.baseY * GRID_WAVE_FREQ + scrollOffset * SCROLL_FREQ) * SCROLL_WAVE_AMP;
        const waveY = Math.cos(dot.baseX * GRID_WAVE_FREQ + scrollOffset * SCROLL_FREQ) * SCROLL_WAVE_AMP;

        dot._finalX = dot.baseX + dot.offsetX + waveX;
        dot._finalY = dot.baseY + dot.offsetY + waveY;

        let alpha = BASE_ALPHA + mouseAlphaBoost;
        if (alpha > 0.4) alpha = 0.4;
        ctx.beginPath();
        ctx.arc(dot._finalX, dot._finalY, DOT_RADIUS, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${WHITISH_COLOR}, ${alpha})`;
        ctx.fill();
      }

      ctx.lineWidth = WEB_LINE_WIDTH;
      ctx.strokeStyle = WEB_LINE_COLOR;
      ctx.beginPath();
      const maxDistSq = 115 * 115;
      for (let i = 0; i < dots.length; i++) {
        const dotA = dots[i];
        for (let j = i + 1; j < dots.length; j++) {
          const dotB = dots[j];
          const dx = dotB._finalX - dotA._finalX;
          const dy = dotB._finalY - dotA._finalY;
          const distSq = dx * dx + dy * dy;
          if (distSq < maxDistSq) {
            ctx.moveTo(dotA._finalX, dotA._finalY);
            ctx.lineTo(dotB._finalX, dotB._finalY);
          }
        }
      }
      ctx.stroke();

      const scaleFactor = FOCAL_LENGTH / (FOCAL_LENGTH + CUBE_DISTANCE);
      const worldMargin = CUBE_SIZE * 1.5;
      const maxWorldX = (width / 2 + worldMargin) / scaleFactor;
      const maxWorldY = (height / 2 + worldMargin) / scaleFactor;

      ctx.lineWidth = CUBE_LINE_WIDTH;
      ctx.strokeStyle = CUBE_LINE_COLOR;
      for (let cube of cubes) {
        cube.rotX += cube.rotSpeedX;
        cube.rotY += cube.rotSpeedY;
        cube.rotZ += cube.rotSpeedZ;
        cube.cx += cube.vx;
        cube.cy += cube.vy;

        if (cube.cx > maxWorldX) cube.cx = -maxWorldX;
        if (cube.cx < -maxWorldX) cube.cx = maxWorldX;
        if (cube.cy > maxWorldY) cube.cy = -maxWorldY;
        if (cube.cy < -maxWorldY) cube.cy = maxWorldY;

        const transformed = cubeVertices.map(v => {
          const rotated = rotatePoint(v[0], v[1], v[2], cube.rotX, cube.rotY, cube.rotZ);
          return project(rotated.x + cube.cx, rotated.y + cube.cy, rotated.z + cube.cz);
        });

        ctx.beginPath();
        for (let edge of cubeEdges) {
          const p1 = transformed[edge[0]];
          const p2 = transformed[edge[1]];
          if (p1 && p2) {
            ctx.moveTo(p1.sx, p1.sy);
            ctx.lineTo(p2.sx, p2.sy);
          }
        }
        ctx.stroke();
      }

      animationFrameId = requestAnimationFrame(animate);
    }

    function handleMouseMove(e: MouseEvent) { mouseX = e.clientX; mouseY = e.clientY; }
    function handleScroll() { scrollY = window.scrollY; }

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    window.addEventListener("scroll", handleScroll, { passive: true });
    animationFrameId = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("scroll", handleScroll);
      if (canvas.parentNode) canvas.parentNode.removeChild(canvas);
    };
  }, []);

  return (
    <div
      className="matrix-container"
      style={{
        color: THEME.text,
        padding: "20px",
        maxWidth: "1200px",
        width: "100%",
        fontFamily: THEME.font,
        backgroundColor: "transparent",
        backgroundImage: `
          linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px)
        `,
        backgroundSize: "60px 60px",
        backgroundPosition: "center center",
        position: "relative",
        zIndex: 1,
      }}
    >
      <div id="turnstile-invisible-container" style={{ display: "none" }}></div>

      {showConfigMatrix && (
        <div
          className="modal-overlay"
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0,0,0,0.85)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            zIndex: 1000,
            padding: "20px",
          }}
        >
          <div
            className="config-matrix-modal"
            style={{
              maxWidth: modalStage === "profile" ? "800px" : "540px",
              width: "100%",
              background: THEME.surface,
              border: `1px solid ${THEME.border}`,
              borderRadius: "6px",
              padding: "25px",
              boxSizing: "border-box",
            }}
          >
            {modalStage !== "profile" && (
              <div style={{ display: "flex", width: "100%", marginBottom: "20px", border: `1px solid ${THEME.border}` }}>
                <button
                  type="button"
                  onClick={() => { setModalStage("login"); setAuthError(null); }}
                  style={{
                    flex: 1,
                    padding: "12px",
                    border: "none",
                    backgroundColor: modalStage === "login" ? THEME.text : THEME.surface,
                    color: modalStage === "login" ? THEME.surface : THEME.text,
                    fontWeight: "bold",
                    fontFamily: THEME.font,
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  SIGN IN GATEWAY
                </button>
                <button
                  type="button"
                  onClick={() => { setModalStage("signup"); setAuthError(null); }}
                  style={{
                    flex: 1,
                    padding: "12px",
                    border: "none",
                    backgroundColor: modalStage === "signup" ? THEME.text : THEME.surface,
                    color: modalStage === "signup" ? THEME.surface : THEME.text,
                    fontWeight: "bold",
                    fontFamily: THEME.font,
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  SIGN UP INSTANTIATION
                </button>
              </div>
            )}

            {modalStage === "login" && (
              <form onSubmit={handleLoginSubmit}>
                <div className="modal-header" style={{ marginBottom: "15px" }}>
                  <h2 style={{ fontSize: "1.2rem", color: THEME.accent, fontFamily: THEME.font }}>
                    GATEWAY IDENTITY CONFIRMATION
                  </h2>
                  <p style={{ color: THEME.textTertiary, fontSize: "0.85rem", margin: "5px 0 0 0", fontFamily: THEME.font }}>
                    Enter administrative sequence parameters.
                  </p>
                </div>

                {authError && (
                  <div
                    style={{
                      color: "#f85149",
                      border: "1px solid #f85149",
                      padding: "10px",
                      margin: "10px 0",
                      fontSize: "0.85rem",
                      background: "rgba(248,81,73,0.05)",
                      fontFamily: THEME.font,
                    }}
                  >
                    [!] EXCEPTION: {authError}
                  </div>
                )}

                <div style={{ display: "flex", flexDirection: "column", gap: "1.2rem", margin: "20px 0" }}>
                  <div className="input-block">
                    <label
                      style={{
                        color: THEME.accent,
                        display: "block",
                        fontSize: "0.8rem",
                        marginBottom: "6px",
                        fontWeight: "bold",
                        fontFamily: THEME.font,
                      }}
                    >
                      USER ASSIGNMENT IDENTIFIER
                    </label>
                    <input
                      type="text"
                      placeholder="Username"
                      required
                      value={username}
                      onChange={(e) => handleSanitizedUsernameChange(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "10px",
                        background: "#0d0d0d",
                        border: `1px solid ${THEME.border}`,
                        color: THEME.text,
                        borderRadius: "4px",
                        fontFamily: THEME.font,
                      }}
                    />
                  </div>
                  <div className="input-block">
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                      <label
                        style={{
                          color: THEME.accent,
                          fontSize: "0.8rem",
                          fontWeight: "bold",
                          fontFamily: THEME.font,
                        }}
                      >
                        CRYPTOGRAPHIC PHRASE MATRIX
                      </label>
                      <div style={{ display: "flex", gap: "12px" }}>
                        <button
                          type="button"
                          onClick={handleCopyCurrentPassword}
                          disabled={!password}
                          style={{
                            background: "none",
                            border: "none",
                            color: THEME.text,
                            fontSize: "0.75rem",
                            cursor: password ? "pointer" : "not-allowed",
                            textDecoration: "underline",
                            padding: 0,
                            opacity: password ? 1 : 0.4,
                            fontFamily: THEME.font,
                          }}
                        >
                          {copiedNotification ? "Copied!" : "Copy Input"}
                        </button>
                      </div>
                    </div>
                    <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                      <input
                        type={showPassword ? "text" : "password"}
                        placeholder="Input complete verification token..."
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        style={{
                          width: "100%",
                          padding: "10px",
                          paddingRight: "40px",
                          background: "#0d0d0d",
                          border: `1px solid ${THEME.border}`,
                          color: THEME.text,
                          borderRadius: "4px",
                          fontFamily: THEME.font,
                        }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{
                          position: "absolute",
                          right: "10px",
                          background: "none",
                          border: "none",
                          color: THEME.textTertiary,
                          cursor: "pointer",
                        }}
                      >
                        <i className={showPassword ? "bi bi-eye-slash" : "bi bi-eye"}></i>
                      </button>
                    </div>
                  </div>
                  <div id="login-turnstile" style={{ margin: "10px 0" }}></div>
                </div>

                <div className="modal-footer" style={{ marginTop: "25px", display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                  <button
                    type="button"
                    className="compile-btn"
                    style={{
                      background: "transparent",
                      color: THEME.text,
                      border: `1px solid ${THEME.border}`,
                      padding: "8px 16px",
                      cursor: "pointer",
                      fontFamily: THEME.font,
                    }}
                    onClick={() => setShowConfigMatrix(false)}
                  >
                    TERMINATE
                  </button>
                  <button
                    type="submit"
                    className="compile-btn"
                    style={{
                      background: THEME.accent,
                      color: THEME.text,
                      border: "none",
                      padding: "8px 16px",
                      fontWeight: "bold",
                      cursor: "pointer",
                      fontFamily: THEME.font,
                    }}
                  >
                    MOUNT ACCESS GATE
                  </button>
                </div>
              </form>
            )}

            {modalStage === "signup" && (
              <form onSubmit={handleSignupSubmit}>
                <div className="modal-header" style={{ marginBottom: "15px" }}>
                  <h2 style={{ fontSize: "1.2rem", color: THEME.accent, fontFamily: THEME.font }}>
                    INITIALIZE IDENTITY ANCHOR
                  </h2>
                  <p style={{ color: THEME.textTertiary, fontSize: "0.85rem", margin: "5px 0 0 0", fontFamily: THEME.font }}>
                    Construct a custom administrative token profile following zero-trust metrics.
                  </p>
                </div>

                {authError && (
                  <div
                    style={{
                      color: "#f85149",
                      border: "1px solid #f85149",
                      padding: "10px",
                      margin: "10px 0",
                      fontSize: "0.85rem",
                      background: "rgba(248,81,73,0.05)",
                      fontFamily: THEME.font,
                    }}
                  >
                    [!] EXCEPTION: {authError}
                  </div>
                )}

                <div style={{ display: "flex", flexDirection: "column", gap: "1.2rem", margin: "20px 0" }}>
                  <div className="input-block">
                    <label
                      style={{
                        color: THEME.accent,
                        display: "block",
                        fontSize: "0.8rem",
                        marginBottom: "6px",
                        fontWeight: "bold",
                        fontFamily: THEME.font,
                      }}
                    >
                      CHOOSE USER IDENTIFIER
                    </label>
                    <input
                      type="text"
                      placeholder="Desired Username (Alphanumeric only)..."
                      required
                      value={username}
                      onChange={(e) => handleSanitizedUsernameChange(e.target.value)}
                      style={{
                        width: "100%",
                        padding: "10px",
                        background: "#0d0d0d",
                        border: `1px solid ${THEME.border}`,
                        color: THEME.text,
                        borderRadius: "4px",
                        fontFamily: THEME.font,
                      }}
                    />
                  </div>
                  <div className="input-block">
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                      <label
                        style={{
                          color: THEME.accent,
                          fontSize: "0.8rem",
                          fontWeight: "bold",
                          fontFamily: THEME.font,
                        }}
                      >
                        CRYPTOGRAPHIC PHRASE MATRIX ({password.length}/128+ chars)
                      </label>
                      <button
                        type="button"
                        onClick={handleCopyCurrentPassword}
                        disabled={!password}
                        style={{
                          background: "none",
                          border: "none",
                          color: THEME.text,
                          fontSize: "0.75rem",
                          cursor: password ? "pointer" : "not-allowed",
                          textDecoration: "underline",
                          padding: 0,
                          opacity: password ? 1 : 0.4,
                          fontFamily: THEME.font,
                        }}
                      >
                        {copiedNotification ? "Copied!" : "Copy Input"}
                      </button>
                    </div>
                    <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                      <input
                        type={showPassword ? "text" : "password"}
                        placeholder="Construct custom complex sequence matrix..."
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        style={{
                          width: "100%",
                          padding: "10px",
                          paddingRight: "40px",
                          background: "#0d0d0d",
                          border: `1px solid ${THEME.border}`,
                          color: THEME.text,
                          borderRadius: "4px",
                          fontFamily: THEME.font,
                        }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{
                          position: "absolute",
                          right: "10px",
                          background: "none",
                          border: "none",
                          color: THEME.textTertiary,
                          cursor: "pointer",
                        }}
                      >
                        <i className={showPassword ? "bi bi-eye-slash" : "bi bi-eye"}></i>
                      </button>
                    </div>
                  </div>
                  <div id="signup-turnstile" style={{ margin: "10px 0" }}></div>
                </div>

                <div
                  style={{
                    fontSize: "0.75rem",
                    background: THEME.surface,
                    border: `1px solid ${THEME.border}`,
                    padding: "12px",
                    borderRadius: "4px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                    fontFamily: THEME.font,
                  }}
                >
                  <div style={{ color: policyCheck.length ? "#3fb950" : "#f85149" }}>
                    {policyCheck.length ? "✓" : "✕"} LENGTH CRITERIA VERIFICATION (&gt;= 128 CHARACTERS)
                  </div>
                  <div style={{ color: policyCheck.upper ? "#3fb950" : "#f85149" }}>
                    {policyCheck.upper ? "✓" : "✕"} UPPERCASE CHARACTER ENCODING SET PRESENCE
                  </div>
                  <div style={{ color: policyCheck.lower ? "#3fb950" : "#f85149" }}>
                    {policyCheck.lower ? "✓" : "✕"} LOWERCASE CHARACTER ENCODING SET PRESENCE
                  </div>
                  <div style={{ color: policyCheck.digit ? "#3fb950" : "#f85149" }}>
                    {policyCheck.digit ? "✓" : "✕"} SCALAR INTEGRAL UNIT NUMERIC PRESENCE
                  </div>
                  <div style={{ color: policyCheck.special ? "#3fb950" : "#f85149" }}>
                    {policyCheck.special ? "✓" : "✕"} SYMBOLIC NON-ALPHANUMERIC METACHING SETS
                  </div>
                </div>

                <div className="modal-footer" style={{ marginTop: "25px", display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                  <button
                    type="button"
                    className="compile-btn"
                    style={{
                      background: "transparent",
                      color: THEME.text,
                      border: `1px solid ${THEME.border}`,
                      padding: "8px 16px",
                      cursor: "pointer",
                      fontFamily: THEME.font,
                    }}
                    onClick={() => setShowConfigMatrix(false)}
                  >
                    TERMINATE
                  </button>
                  <button
                    type="submit"
                    className="compile-btn"
                    disabled={!isFormCompliant}
                    style={{
                      background: isFormCompliant ? THEME.accent : "#222",
                      color: isFormCompliant ? THEME.text : THEME.textTertiary,
                      border: "none",
                      padding: "8px 16px",
                      fontWeight: "bold",
                      cursor: isFormCompliant ? "pointer" : "not-allowed",
                      opacity: isFormCompliant ? 1 : 0.5,
                      fontFamily: THEME.font,
                    }}
                  >
                    COMPILE REGISTER
                  </button>
                </div>
              </form>
            )}

            {modalStage === "profile" && (
              <div>
                <div className="modal-header" style={{ marginBottom: "15px" }}>
                  <h2 style={{ fontSize: "1.2rem", color: THEME.accent, fontFamily: THEME.font }}>
                    INITIALIZE TRACKING PROFILE
                  </h2>
                  <p style={{ color: THEME.textTertiary, fontSize: "0.85rem", fontFamily: THEME.font }}>
                    Select matrix nodes to isolate parameters across the tracking stream.
                  </p>
                </div>

                <div className="modal-search-bar" style={{ marginBottom: "15px" }}>
                  <input
                    type="text"
                    placeholder="> Search library tags or define custom parameters..."
                    value={configSearch}
                    onChange={(e) => setConfigSearch(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "10px",
                      background: "#0d0d0d",
                      border: `1px solid ${THEME.border}`,
                      color: THEME.text,
                      borderRadius: "4px",
                      fontFamily: THEME.font,
                    }}
                  />
                </div>

                <div
                  className="modal-body"
                  style={{
                    maxHeight: "300px",
                    overflowY: "auto",
                    display: "block",
                    paddingRight: "5px",
                    marginBottom: "20px",
                  }}
                >
                  {isSearchCustom && (
                    <div className="topic-group" style={{ marginBottom: "15px" }}>
                      <h3 style={{ fontSize: "0.85rem", color: THEME.accent, margin: "0 0 5px 0", fontFamily: THEME.font }}>
                        [ Custom Parameter Matrix ]
                      </h3>
                      <div className="tag-cloud">
                        <button
                          type="button"
                          className={`matrix-tag custom-tag-btn ${
                            userProfileTags.includes(configSearch.trim().toUpperCase()) ? "selected" : ""
                          }`}
                          onClick={() => toggleTag(configSearch)}
                          style={{
                            background: userProfileTags.includes(configSearch.trim().toUpperCase())
                              ? THEME.text
                              : "#222",
                            color: userProfileTags.includes(configSearch.trim().toUpperCase())
                              ? THEME.surface
                              : THEME.accent,
                            border: `1px solid ${THEME.accent}`,
                            padding: "5px 10px",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontFamily: THEME.font,
                          }}
                        >
                          + ADD "{configSearch.trim().toUpperCase()}"
                        </button>
                      </div>
                    </div>
                  )}

                  {Object.entries(TOPIC_DATABASE).map(([categoryName, tags]) => {
                    const visibleTags = tags.filter((tag) => tag.toLowerCase().includes(configSearch.toLowerCase()));
                    if (visibleTags.length === 0) return null;
                    return (
                      <div className="topic-group" key={categoryName} style={{ marginBottom: "15px" }}>
                        <h3
                          style={{
                            fontSize: "0.85rem",
                            color: THEME.textTertiary,
                            margin: "0 0 8px 0",
                            textTransform: "uppercase",
                            fontFamily: THEME.font,
                          }}
                        >
                          [ {categoryName} ]
                        </h3>
                        <div className="tag-cloud" style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                          {visibleTags.map((tag) => {
                            const isChosen = userProfileTags.includes(tag.toUpperCase());
                            return (
                              <button
                                key={tag}
                                type="button"
                                className={`matrix-tag ${isChosen ? "selected" : ""}`}
                                onClick={() => toggleTag(tag)}
                                style={{
                                  background: isChosen ? THEME.text : "#0d0d0d",
                                  color: isChosen ? THEME.surface : THEME.text,
                                  border: isChosen ? `1px solid ${THEME.text}` : `1px solid ${THEME.border}`,
                                  padding: "5px 10px",
                                  borderRadius: "4px",
                                  cursor: "pointer",
                                  fontSize: "0.85rem",
                                  fontWeight: isChosen ? "bold" : "normal",
                                  fontFamily: THEME.font,
                                }}
                              >
                                {tag}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}

                  {userProfileTags.length > 0 && (
                    <div
                      className="topic-group selected-group"
                      style={{
                        marginTop: "20px",
                        borderTop: `1px dashed ${THEME.border}`,
                        paddingTop: "15px",
                      }}
                    >
                      <h3 style={{ fontSize: "0.85rem", color: THEME.text, margin: "0 0 8px 0", fontFamily: THEME.font }}>
                        [ Target Profile Definitions ]
                      </h3>
                      <div className="tag-cloud" style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                        {userProfileTags.map((tag) => (
                          <button
                            key={tag}
                            type="button"
                            className="matrix-tag selected remove-tag"
                            onClick={() => toggleTag(tag)}
                            title="Remove Parameter"
                            style={{
                              background: THEME.text,
                              color: THEME.surface,
                              padding: "5px 10px",
                              borderRadius: "4px",
                              border: "none",
                              cursor: "pointer",
                              fontWeight: "bold",
                              fontSize: "0.85rem",
                              fontFamily: THEME.font,
                            }}
                          >
                            {tag} ✕
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div
                  className="modal-footer"
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    borderTop: `1px solid ${THEME.border}`,
                    paddingTop: "15px",
                  }}
                >
                  <span
                    className="selected-count"
                    style={{ fontSize: "0.85rem", color: THEME.textTertiary, fontFamily: THEME.font }}
                  >
                    NODES PROFILED: {userProfileTags.length}
                  </span>
                  <button
                    type="button"
                    className="compile-btn"
                    onClick={() => setShowConfigMatrix(false)}
                    style={{
                      background: THEME.accent,
                      color: THEME.text,
                      border: "none",
                      padding: "8px 16px",
                      fontWeight: "bold",
                      cursor: "pointer",
                      fontFamily: THEME.font,
                    }}
                  >
                    COMPILE CONFIGURATION
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <header className="matrix-header" style={{ marginBottom: "20px" }}>
        <div className="terminal-title">
          <h1 style={{ color: THEME.accent, margin: 0, fontFamily: THEME.font }}>THREAT-MATRIX</h1>
        </div>
      </header>

      <div
        className="auth-status-bar"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: THEME.surface,
          padding: "10px",
          borderRadius: "4px",
          marginBottom: "20px",
          border: `1px solid ${THEME.border}`,
        }}
      >
        <div>
          <span style={{ fontFamily: THEME.font }}>OPERATIONAL_MODE: </span>
          <strong style={{ color: isAuthenticated ? "#3fb950" : "#f0883e", fontFamily: THEME.font }}>
            {isAuthenticated ? "AUTHENTICATED" : "ANONYMOUS"}
          </strong>
        </div>

        <div style={{ display: "flex", gap: "1rem" }}>
          <button
            className="terminal-link-btn"
            onClick={clearCacheAndReload}
            style={{
              background: "transparent",
              color: THEME.text,
              border: `1px solid ${THEME.border}`,
              padding: "0.3rem 0.8rem",
              cursor: "pointer",
              fontFamily: THEME.font,
            }}
          >
            Clear Cache
          </button>

          {isAuthenticated ? (
            <button
              className="terminal-link-btn"
              onClick={handleDisconnect}
              style={{
                background: "transparent",
                color: "#f85149",
                border: "1px solid #f85149",
                padding: "0.3rem 0.8rem",
                fontWeight: "bold",
                cursor: "pointer",
                transition: "all 0.2s",
                fontFamily: THEME.font,
              }}
            >
              Logout
            </button>
          ) : (
            <button
              className="terminal-link-btn"
              onClick={() => {
                setShowConfigMatrix(true);
                setModalStage("login");
              }}
              style={{
                background: THEME.accent,
                color: THEME.text,
                border: "none",
                padding: "0.3rem 0.8rem",
                fontWeight: "bold",
                cursor: "pointer",
                fontFamily: THEME.font,
              }}
            >
              Initialize Profile
            </button>
          )}
        </div>
      </div>

      <section
        className="control-hub"
        style={{
          background: THEME.surface,
          padding: "15px",
          borderRadius: "4px",
          border: `1px solid ${THEME.border}`,
          marginBottom: "20px",
        }}
      >
        <span
          className="control-label"
          style={{
            color: THEME.textTertiary,
            fontSize: "0.8rem",
            marginBottom: "10px",
            display: "block",
            fontFamily: THEME.font,
          }}
        >
          Query Parameters
        </span>
        <div
          className="filter-inputs-row"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "15px",
          }}
        >
          <div className="input-block">
            <label
              style={{
                display: "block",
                fontSize: "0.8rem",
                color: THEME.textSecondary,
                marginBottom: "5px",
                fontFamily: THEME.font,
              }}
            >
              Global Feed Search
            </label>
            <input
              type="text"
              disabled={!isAuthenticated}
              placeholder={isAuthenticated ? "Search payloads, CVEs..." : "Pipeline locked..."}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                width: "100%",
                padding: "8px",
                background: "#0d0d0d",
                border: `1px solid ${THEME.border}`,
                color: THEME.text,
                borderRadius: "4px",
                fontFamily: THEME.font,
              }}
            />
          </div>

          <div className="input-block">
            <label
              style={{
                display: "block",
                fontSize: "0.8rem",
                color: THEME.textSecondary,
                marginBottom: "5px",
                fontFamily: THEME.font,
              }}
            >
              Topic Track Isolation
            </label>
            <select
              disabled={!isAuthenticated}
              value={selectedTopic}
              onChange={(e) => setSelectedTopic(e.target.value)}
              style={{
                width: "100%",
                padding: "8px",
                background: "#0d0d0d",
                border: `1px solid ${THEME.border}`,
                color: THEME.text,
                borderRadius: "4px",
                fontFamily: THEME.font,
              }}
            >
              <option value="">-- All Public Categories --</option>
              {allTags.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </div>

          <div className="input-block">
            <label
              style={{
                display: "block",
                fontSize: "0.8rem",
                color: THEME.textSecondary,
                marginBottom: "5px",
                fontFamily: THEME.font,
              }}
            >
              Source Pipeline
            </label>
            <select
              disabled={!isAuthenticated}
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              style={{
                width: "100%",
                padding: "8px",
                background: "#0d0d0d",
                border: `1px solid ${THEME.border}`,
                color: THEME.text,
                borderRadius: "4px",
                fontFamily: THEME.font,
              }}
            >
              <option value="">-- All Intelligence Sources --</option>
              <option value="CISA">CISA KEV (Critical Exploits)</option>
              <option value="NVD">NVD (Standard CVEs)</option>
              <option value="CIRCL">CIRCL</option>
              <option value="NewsAPI">Security News</option>
            </select>
          </div>

          <div className="input-block">
            <label
              style={{
                display: "block",
                fontSize: "0.8rem",
                color: THEME.textSecondary,
                marginBottom: "5px",
                fontFamily: THEME.font,
              }}
            >
              Origin Date Window
            </label>
            <input
              type="date"
              disabled={!isAuthenticated}
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              style={{
                width: "100%",
                padding: "8px",
                background: "#0d0d0d",
                border: `1px solid ${THEME.border}`,
                color: THEME.text,
                borderRadius: "4px",
                fontFamily: THEME.font,
              }}
            />
          </div>
        </div>
      </section>

      <div style={{ display: "flex", width: "100%", marginTop: "1rem", marginBottom: "1rem" }}>
        <button
          onClick={() => setActiveFeedTab("cluster")}
          style={{
            flex: 1,
            padding: "0.75rem",
            border: `1px solid ${THEME.border}`,
            backgroundColor: activeFeedTab === "cluster" ? THEME.text : THEME.surface,
            color: activeFeedTab === "cluster" ? THEME.surface : THEME.text,
            fontWeight: "bold",
            cursor: "pointer",
            fontFamily: THEME.font,
          }}
        >
          CLUSTER FEED
        </button>
        {isAuthenticated && (
          <button
            onClick={() => setActiveFeedTab("selective")}
            style={{
              flex: 1,
              padding: "0.75rem",
              border: `1px solid ${THEME.border}`,
              backgroundColor: activeFeedTab === "selective" ? THEME.text : THEME.surface,
              color: activeFeedTab === "selective" ? THEME.surface : THEME.text,
              fontWeight: "bold",
              cursor: "pointer",
              fontFamily: THEME.font,
            }}
          >
            SELECTIVE FEED
          </button>
        )}
      </div>

      {loading && (
        <div
          className="state-container"
          style={{
            padding: "40px",
            border: `1px dashed ${THEME.border}`,
            textAlign: "center",
            color: THEME.accent,
            fontFamily: THEME.font,
          }}
        >
          &gt; Streaming aggregated matrix channels via edge routing infrastructure...
        </div>
      )}

      {error && (
        <div
          className="state-container"
          style={{
            padding: "40px",
            border: "1px solid #f85149",
            background: "rgba(248,81,73,0.05)",
            color: "#f85149",
            fontFamily: THEME.font,
            borderRadius: "4px",
          }}
        >
          [!] SYSTEM HOLD: {error}
        </div>
      )}

      {!loading && !error && (
        <>
          {activeFeedTab === "cluster" && (
            <main className="matrix-list-stream">
              {filteredLogs.length === 0 ? (
                <div
                  className="state-container"
                  style={{
                    padding: "40px",
                    border: `1px dashed ${THEME.border}`,
                    textAlign: "center",
                    color: THEME.textTertiary,
                    fontFamily: THEME.font,
                  }}
                >
                  &gt; No public threat units currently routed.
                </div>
              ) : (
                filteredLogs.map((log) => {
                  try {
                    return renderCard(log);
                  } catch (e) {
                    return null;
                  }
                })
              )}
            </main>
          )}

          {activeFeedTab === "selective" && (
            <main className="matrix-list-stream">
              {userProfileTags.length === 0 ? (
                <div
                  className="state-container"
                  style={{
                    padding: "40px",
                    border: `1px dashed ${THEME.border}`,
                    textAlign: "center",
                    color: THEME.textTertiary,
                    fontFamily: THEME.font,
                  }}
                >
                  No profile tags selected – add tags to populate this feed.
                </div>
              ) : profileFilteredLogs.length === 0 ? (
                <div
                  className="state-container"
                  style={{
                    padding: "40px",
                    border: `1px dashed ${THEME.border}`,
                    textAlign: "center",
                    color: THEME.textTertiary,
                    fontFamily: THEME.font,
                  }}
                >
                  &gt; No items match your specified profile and current filters.
                </div>
              ) : (
                profileFilteredLogs.map((log) => {
                  try {
                    return renderCard(log);
                  } catch (e) {
                    return null;
                  }
                })
              )}
            </main>
          )}
        </>
      )}
    </div>
  );
}