const { useState, useEffect, useMemo } = React;

// --- Runtime Global Proxies & Fallbacks ---
// IconFallback prevents React Error #130 if a Lucide icon is undefined
const IconFallback = (props) => (
    <div {...props} className={`inline-block border border-red-500/20 bg-red-500/5 rounded p-1 ${props.className}`}>
        <span className="text-[8px] text-red-500 font-bold">ERR</span>
    </div>
);

const lucide = new Proxy({}, {
    get: (target, prop) => (window.LucideReact || window.lucide || {})[prop] || IconFallback
});

const Recharts = new Proxy({}, {
    get: (target, prop) => (window.Recharts || window.recharts || {})[prop]
});

// --- Error Guardian ---
window.onerror = function (msg, url, line, col, error) {
    console.error("AEGIS_RUNTIME_ERROR:", { msg, url, line, col, error });
};

// --- Theme Utility ---
const StatusChip = ({ type, children }) => {
    const styles = {
        safe: "bg-aegis-success/10 text-aegis-success border-aegis-success/20",
        malicious: "bg-aegis-accent/10 text-aegis-accent border-aegis-accent/20",
        ambiguous: "bg-aegis-warning/10 text-aegis-warning border-aegis-warning/20",
        info: "bg-aegis-primary/10 text-aegis-primary border-aegis-primary/20",
        critical: "bg-red-500/10 text-red-500 border-red-500/20",
        high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
        medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
        low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border uppercase tracking-wider ${styles[type.toLowerCase()] || styles.info}`}>
            {children}
        </span>
    );
};

// --- API Helpers ---
const API = {
    async fetch(endpoint, options = {}) {
        const res = await fetch('/api' + endpoint, options);
        if (res.status === 401 && !endpoint.includes('/auth/status')) {
            window.location.reload();
            return {};
        }
        return res.json();
    }
};

// --- Main Components ---

const Sidebar = ({ activePage, setActivePage, onLogout }) => {
    const { LayoutDashboard, Activity, Logs, Shield, Settings, ChevronRight, LogOut, Check } = lucide;
    const menu = [
        { id: 'command', name: 'Dashboard', icon: LayoutDashboard },
        { id: 'analytics', name: 'Analysis', icon: Activity },
        { id: 'logs', name: 'Threat Intel', icon: Logs },
        { id: 'rules', name: 'Ruleset', icon: Shield },
        { id: 'config', name: 'Settings', icon: Settings },
    ];

    return (
        <aside className="w-64 glass border-r border-slate-800 flex flex-col h-full z-20 relative">
            <div className="absolute top-0 right-0 w-px h-full bg-gradient-to-b from-transparent via-aegis-primary/20 to-transparent"></div>
            <div className="p-8 flex items-center gap-4">
                <div className="w-12 h-12 bg-aegis-primary rounded-xl flex items-center justify-center shadow-2xl shadow-aegis-primary/40 group cursor-pointer overflow-hidden relative">
                    <div className="absolute inset-0 bg-white/10 group-hover:translate-y-full transition-transform duration-500"></div>
                    <Shield className="text-white relative z-10" size={28} />
                </div>
                <div>
                    <h1 className="font-black text-xl tracking-tighter text-white">AEGIS<span className="text-aegis-primary">.RS 🛡️</span></h1>
                    <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-aegis-success rounded-full animate-pulse shadow-sm shadow-aegis-success"></span>
                        <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Proxy Active</p>
                    </div>
                </div>
            </div>

            <nav className="flex-1 px-4 space-y-1 mt-6">
                {menu.map(item => (
                    <button
                        key={item.id}
                        onClick={() => setActivePage(item.id)}
                        className={`w-full flex items-center gap-4 px-5 py-4 rounded-2xl transition-all duration-300 group relative overflow-hidden ${activePage === item.id
                            ? 'text-white'
                            : 'text-slate-500 hover:text-slate-200'
                            }`}
                    >
                        {activePage === item.id && (
                            <div className="absolute inset-0 bg-gradient-to-r from-aegis-primary/20 to-transparent border-l-2 border-aegis-primary animate-in slide-in-from-left-4 duration-500"></div>
                        )}
                        <item.icon size={22} className={`${activePage === item.id ? 'text-aegis-primary' : 'group-hover:text-slate-300'} transition-colors relative z-10`} />
                        <span className="font-bold text-sm relative z-10">{item.name}</span>
                        {activePage === item.id && <ChevronRight size={14} className="ml-auto text-aegis-primary animate-in fade-in duration-700" />}
                    </button>
                ))}
            </nav>

            <div className="p-6">
                <div className="p-4 bg-slate-900/50 rounded-2xl border border-slate-800/50 mb-6">
                    <p className="text-[10px] font-bold text-slate-600 uppercase mb-2">Build Integrity</p>
                    <div className="flex justify-between items-end">
                        <span className="text-xs font-mono text-aegis-success italic">STABLE-0.1.0</span>
                        <Check size={14} className="text-aegis-success" />
                    </div>
                </div>
                <button
                    onClick={onLogout}
                    className="w-full flex items-center gap-3 px-5 py-4 text-slate-500 hover:text-aegis-accent hover:bg-aegis-accent/5 rounded-2xl transition-all font-bold text-sm"
                >
                    <LogOut size={20} />
                    <span>Disconnect</span>
                </button>
            </div>
        </aside>
    );
};

const LoginPanel = ({ onLogin }) => {
    const { Lock, AlertTriangle, RefreshCw, Shield } = lucide;
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const data = await res.json();
            if (res.ok) onLogin();
            else setError(data.error || 'Invalid credentials');
        } catch (err) {
            setError('Proxy uplink unstable.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-dark-300 flex items-center justify-center p-6 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(circle_at_50%_50%,#0ea5e910,transparent_50%)]"></div>
            <div className="absolute bottom-0 right-0 w-96 h-96 bg-aegis-primary/5 rounded-full blur-[100px]"></div>

            <div className="max-w-md w-full glass border border-slate-800 rounded-[2.5rem] p-10 shadow-2xl relative z-10">
                <div className="flex flex-col items-center mb-10 text-center">
                    <div className="w-20 h-20 bg-gradient-to-br from-aegis-primary to-aegis-secondary rounded-3xl flex items-center justify-center mb-6 shadow-2xl shadow-aegis-primary/30 transform hover:rotate-3 transition-transform">
                        <Lock className="text-white" size={36} />
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Proxy Gateway 🛡️</h1>
                    <p className="text-slate-500 text-sm mt-2 font-medium">Accessing Aegis.rs Secure LLM Gateway</p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-8">
                    <div className="relative group">
                        <label className="block text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3 ml-1 group-focus-within:text-aegis-primary transition-colors">Administrator Key</label>
                        <div className="relative">
                            <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 transition-colors group-focus-within:text-aegis-primary" size={20} />
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full bg-dark-200 border border-slate-800/50 group-hover:border-slate-700 rounded-2xl pl-12 pr-4 py-4 focus:outline-none focus:border-aegis-primary transition-all font-mono text-lg text-white"
                                placeholder="••••••••••••••••"
                                autoFocus
                            />
                        </div>
                    </div>

                    {error && (
                        <div className="bg-aegis-accent/5 border border-aegis-accent/20 text-aegis-accent px-5 py-4 rounded-2xl text-xs font-bold flex items-center gap-3 animate-bounce">
                            <AlertTriangle size={18} />
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-gradient-to-r from-aegis-primary to-aegis-secondary hover:brightness-110 active:scale-[0.98] text-white font-black text-md py-4 rounded-2xl shadow-xl shadow-aegis-primary/25 transition-all flex items-center justify-center gap-3 uppercase tracking-wider"
                    >
                        {loading ? <RefreshCw className="animate-spin" size={22} /> : (<><Shield size={20} /> Connect to Secure Proxy</>)}
                    </button>
                </form>

                <p className="mt-10 text-center text-slate-600 text-[10px] uppercase font-bold tracking-[0.3em]">Aegis Integrity Protection Unit</p>
            </div>
        </div>
    );
};

const CommandCenter = ({ stats, logs, nodeLabel }) => {
    const { ShieldAlert, Server, Cpu, Activity } = lucide;
    const { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } = Recharts;

    const chartData = useMemo(() => logs.slice(-30).map((l, i) => ({
        time: new Date(l.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        v: l.verdict === 'Malicious' ? 10 : 2
    })), [logs]);
    const total = Number(stats.total_requests || 0);
    const blocked = Number(stats.blocked_requests || 0);
    const forwarded = Number(stats.forwarded_requests || 0);
    const flagged = Number(stats.flagged_requests || 0);
    const avgLatencyMs = Number(stats.avg_latency_ms || 0);
    const requestsPerSecond = Number(stats.requests_per_second || 0);
    const blockRate = total > 0 ? (blocked / total) * 100 : 0;
    const allowRate = total > 0 ? (forwarded / total) * 100 : 0;

    const cards = [
        {
            name: 'Request Volume',
            value: total,
            trend: `${requestsPerSecond.toFixed(1)} req/s`,
            trendClass: 'text-aegis-primary',
            icon: Activity,
            color: 'text-aegis-primary',
            bg: 'bg-aegis-primary/10'
        },
        {
            name: 'Neutralized',
            value: blocked,
            trend: `${blockRate.toFixed(1)}% block rate`,
            trendClass: blockRate > 20 ? 'text-aegis-accent' : 'text-slate-500',
            icon: ShieldAlert,
            color: 'text-aegis-accent',
            bg: 'bg-aegis-accent/10'
        },
        {
            name: 'Forwarded',
            value: forwarded,
            trend: `${allowRate.toFixed(1)}% allow rate`,
            trendClass: 'text-aegis-success',
            icon: Server,
            color: 'text-aegis-success',
            bg: 'bg-aegis-success/10'
        },
        {
            name: 'System Latency',
            value: `${avgLatencyMs.toFixed(1)}ms`,
            trend: `${flagged} flagged`,
            trendClass: flagged > 0 ? 'text-aegis-warning' : 'text-slate-500',
            icon: Cpu,
            color: 'text-aegis-secondary',
            bg: 'bg-aegis-secondary/10'
        },
    ];

    return (
        <div className="p-10 space-y-10 animate-in fade-in slide-in-from-bottom-5 duration-700 h-full overflow-y-auto pb-20 custom-scrollbar">
            <header className="flex justify-between items-start">
                <div>
                    <h2 className="text-4xl font-black text-white tracking-tighter">Dashboard 🛡️</h2>
                    <p className="text-slate-500 font-medium mt-1 uppercase text-xs tracking-widest flex items-center gap-2">
                        <span className="w-2 h-2 bg-aegis-primary rounded-full animate-ping"></span>
                        Deep Monitoring Active
                    </p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="glass px-4 py-3 rounded-2xl border border-slate-800 text-[10px] font-bold uppercase tracking-widest text-slate-400">
                        Node: <span className="text-aegis-primary ml-1">{nodeLabel || 'UNKNOWN-EDGE-01'}</span>
                    </div>
                </div>
            </header>

            {/* Advanced Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                {cards.map(s => (
                    <div key={s.name} className="glass group cursor-pointer relative overflow-hidden p-8 rounded-[2rem] border border-slate-800 hover:border-aegis-primary/30 transition-all">
                        <div className="flex justify-between items-start mb-6">
                            <div className={`p-4 rounded-2xl ${s.bg} border border-white/5 group-hover:scale-110 transition-transform`}>
                                <s.icon className={s.color} size={28} />
                            </div>
                            <span className={`text-[10px] font-black uppercase tracking-widest ${s.trendClass}`}>{s.trend}</span>
                        </div>
                        <h3 className="text-4xl font-black text-white mb-2">{typeof s.value === 'number' ? s.value.toLocaleString() : s.value}</h3>
                        <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">{s.name}</p>
                    </div>
                ))}
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-10">
                {/* Traffic Chart */}
                <div className="xl:col-span-2 glass p-10 rounded-[2.5rem] border border-slate-800">
                    <div className="flex justify-between items-center mb-10">
                        <div>
                            <h3 className="text-2xl font-black text-white tracking-tight">Traffic Orchestration</h3>
                            <p className="text-slate-500 text-sm">Synchronized real-time request flow audit</p>
                        </div>
                        <div className="flex gap-2">
                            <span className="w-3 h-3 bg-aegis-primary rounded-full"></span>
                            <span className="w-3 h-3 bg-slate-800 rounded-full"></span>
                        </div>
                    </div>
                    <div className="h-[24rem]">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={chartData}>
                                <defs>
                                    <linearGradient id="colorV" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                                <YAxis stroke="#475569" fontSize={10} tickLine={false} axisLine={false} />
                                <Tooltip
                                    contentStyle={{ background: '#020617', border: '1px solid #1e293b', borderRadius: '16px', fontWeight: 'bold' }}
                                    labelStyle={{ color: '#94a3b8' }}
                                />
                                <Area type="stepAfter" dataKey="v" stroke="#0ea5e9" strokeWidth={4} fillOpacity={1} fill="url(#colorV)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Hot Logs */}
                <div className="glass p-10 rounded-[2.5rem] border border-slate-800 flex flex-col">
                    <h3 className="text-2xl font-black text-white tracking-tight mb-8">Security Pulse</h3>
                    <div className="space-y-6 flex-1 overflow-y-auto pr-3 custom-scrollbar">
                        {logs.slice(0, 15).map((log, i) => (
                            <div key={log.id} className="p-6 rounded-3xl bg-slate-900/40 border border-slate-800/50 hover:border-slate-700 transition-all flex items-center gap-6 group">
                                <div className={`w-3 h-3 rounded-full shrink-0 shadow-lg ${log.verdict === 'Malicious' ? 'bg-aegis-accent shadow-aegis-accent/40 animate-pulse' : 'bg-aegis-success shadow-aegis-success/40'}`} />
                                <div className="min-w-0 flex-1">
                                    <div className="flex justify-between items-center mb-1">
                                        <p className="text-[10px] font-black text-slate-500 font-mono tracking-tighter uppercase">{new Date(log.timestamp).toLocaleTimeString()}</p>
                                        <StatusChip type={log.verdict}>{log.verdict}</StatusChip>
                                    </div>
                                    <p className="text-sm font-black text-slate-200 truncate group-hover:text-aegis-primary transition-colors">{log.meta?.ip || 'SEC-INTERNAL'}</p>
                                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest truncate">{log.detection_result?.reasoning}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

const Analytics = ({ logs, stats }) => {
    const { ShieldCheck } = lucide;
    const { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } = Recharts;

    const attackDist = useMemo(() => {
        const counts = {};
        logs.filter(l => l.verdict === 'Malicious').forEach(l => {
            const cat = l.detection_result?.attack_type || 'Unknown';
            counts[cat] = (counts[cat] || 0) + 1;
        });
        return Object.entries(counts).map(([name, value]) => ({ name, value }));
    }, [logs]);

    const timeline = useMemo(() => {
        const buckets = {};
        logs.forEach(l => {
            const t = new Date(l.timestamp).toLocaleTimeString([], { hour: '2-digit' });
            if (!buckets[t]) buckets[t] = { time: t, safe: 0, threat: 0 };
            if (l.verdict === 'Safe') buckets[t].safe++;
            else buckets[t].threat++;
        });
        return Object.values(buckets).slice(-24);
    }, [logs]);

    const COLORS = ['#0ea5e9', '#6366f1', '#f43f5e', '#10b981', '#f59e0b'];

    return (
        <div className="p-10 space-y-10 animate-in fade-in slide-in-from-left-5 h-full overflow-y-auto pb-20 custom-scrollbar">
            <header>
                <h2 className="text-4xl font-black text-white tracking-tighter">Deep Analytics</h2>
                <p className="text-slate-500 font-medium">Multidimensional threat distribution and vector analysis</p>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
                <div className="glass p-10 rounded-[2.5rem] border border-slate-800">
                    <h3 className="text-xl font-bold mb-8">Attack Vectors</h3>
                    <div className="h-80 flex items-center justify-center">
                        {attackDist.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie data={attackDist} innerRadius={80} outerRadius={120} paddingAngle={5} dataKey="value">
                                        {attackDist.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                                    </Pie>
                                    <Tooltip contentStyle={{ background: '#020617', border: 'none', borderRadius: '12px' }} />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="text-slate-600 flex flex-col items-center gap-4">
                                <ShieldCheck size={64} className="opacity-10" />
                                <p className="font-bold uppercase tracking-widest text-[10px]">No threats logged for analysis</p>
                            </div>
                        )}
                    </div>
                </div>

                <div className="glass p-10 rounded-[2.5rem] border border-slate-800">
                    <h3 className="text-xl font-bold mb-8">Hourly Engagement</h3>
                    <div className="h-80">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={timeline}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                <XAxis dataKey="time" stroke="#475569" fontSize={10} />
                                <YAxis stroke="#475569" fontSize={10} />
                                <Tooltip cursor={{ fill: '#ffffff05' }} contentStyle={{ background: '#020617', border: 'none', borderRadius: '12px' }} />
                                <Bar dataKey="safe" fill="#10b981" radius={[4, 4, 0, 0]} />
                                <Bar dataKey="threat" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};

const AttackLogs = ({ logs, onExport }) => {
    const { Terminal, Logs, Search, RefreshCw, X, Copy, MousePointer2, Activity, ShieldCheck, Shield } = lucide;
    const [search, setSearch] = useState('');
    const [selectedLog, setSelectedLog] = useState(null);

    const filteredLogs = logs.filter(l =>
        l.detection_result?.reasoning?.toLowerCase().includes(search.toLowerCase()) ||
        l.meta?.ip?.includes(search) ||
        l.verdict.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div className="p-10 space-y-10 h-full flex flex-col animate-in fade-in duration-500">
            <div className="flex justify-between items-end">
                <div>
                    <h2 className="text-4xl font-black text-white tracking-tighter">Threat Intelligence</h2>
                    <p className="text-slate-500 font-medium">Forensic inspection of unified threat telemetry</p>
                </div>
                <div className="flex gap-4">
                    <button onClick={() => onExport('json')} className="flex items-center gap-2 glass bg-slate-800/50 hover:bg-slate-700 px-6 py-3 rounded-2xl border border-slate-700 transition-all text-xs font-black uppercase tracking-widest">
                        <Terminal size={16} className="text-aegis-primary" /> Export JSON
                    </button>
                    <button onClick={() => onExport('csv')} className="flex items-center gap-2 glass bg-slate-800/50 hover:bg-slate-700 px-6 py-3 rounded-2xl border border-slate-700 transition-all text-xs font-black uppercase tracking-widest">
                        <Logs size={16} className="text-aegis-secondary" /> Export CSV
                    </button>
                </div>
            </div>

            <div className="flex-1 glass border border-slate-800 rounded-[2.5rem] overflow-hidden flex flex-col shadow-2xl">
                <div className="p-8 border-b border-slate-800 flex gap-6 bg-slate-900/40">
                    <div className="relative flex-1 group">
                        <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-aegis-primary transition-colors" size={20} />
                        <input
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            placeholder="Universal search: IP, Signature, Verdict..."
                            className="w-full bg-dark-200/50 border border-slate-800/50 rounded-2xl pl-14 pr-6 py-4 focus:outline-none focus:border-aegis-primary/50 transition-all text-sm font-medium text-white shadow-inner"
                        />
                    </div>
                    <button className="p-4 bg-slate-800 rounded-2xl border border-slate-700 hover:border-aegis-primary transition-all text-slate-400 hover:text-white">
                        <RefreshCw size={22} />
                    </button>
                </div>

                <div className="flex-1 overflow-auto custom-scrollbar">
                    <table className="w-full text-left border-collapse">
                        <thead className="sticky top-0 bg-dark-200 z-10 border-b border-slate-800">
                            <tr>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-500 uppercase tracking-widest">Capture Time</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-500 uppercase tracking-widest">Source Entity</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-500 uppercase tracking-widest text-center">Verdict</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-500 uppercase tracking-widest">Forensic Reasoning</th>
                                <th className="px-8 py-5 text-[10px] font-black text-slate-500 uppercase tracking-widest text-right">Ops</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50">
                            {filteredLogs.map(log => (
                                <tr key={log.id} className="hover:bg-aegis-primary/[0.03] transition-colors group cursor-pointer" onClick={() => setSelectedLog(log)}>
                                    <td className="px-8 py-5 text-xs font-mono text-slate-500 group-hover:text-slate-300 transition-colors uppercase">{new Date(log.timestamp).toLocaleString()}</td>
                                    <td className="px-8 py-5 text-sm font-black text-white tracking-tight">{log.meta?.ip || 'LOCAL-SOCKET'}</td>
                                    <td className="px-8 py-5 text-center">
                                        <StatusChip type={log.verdict}>{log.verdict}</StatusChip>
                                    </td>
                                    <td className="px-8 py-5 text-xs text-slate-400 max-w-sm truncate italic group-hover:text-slate-300 transition-colors">{log.detection_result?.reasoning}</td>
                                    <td className="px-8 py-5 text-right">
                                        <button className="text-aegis-primary hover:text-white p-2 rounded-xl group-hover:bg-aegis-primary/20 transition-all opacity-0 group-hover:opacity-100">
                                            <MousePointer2 size={20} />
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {filteredLogs.length === 0 && (
                        <div className="h-full flex flex-col items-center justify-center p-20 text-slate-600">
                            <Activity size={80} className="opacity-10 mb-6" />
                            <p className="font-black uppercase tracking-[0.3em] text-xs">No matching telemetry found</p>
                        </div>
                    )}
                </div>
            </div>

            {selectedLog && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-10 glass bg-dark-300/80 backdrop-blur-xl animate-in fade-in duration-300">
                    <div className="max-w-5xl w-full bg-dark-200 border border-white/10 rounded-[3rem] shadow-2xl overflow-hidden animate-in zoom-in slide-in-from-bottom-5 duration-500">
                        <div className="flex justify-between items-center px-10 py-8 border-b border-white/5 bg-white/5">
                            <div>
                                <h3 className="text-2xl font-black text-white tracking-tighter">Event Fragment</h3>
                                <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mt-1">ID: {selectedLog.id}</p>
                            </div>
                            <button onClick={() => setSelectedLog(null)} className="p-3 hover:bg-white/10 rounded-2xl transition-all text-white"><X size={24} /></button>
                        </div>
                        <div className="p-10 lg:flex gap-12">
                            <div className="lg:w-3/5 space-y-8">
                                <section>
                                    <label className="text-[10px] font-black text-aegis-primary uppercase tracking-widest mb-4 block">Request Payload</label>
                                    <div className="relative group">
                                        <pre className="p-6 bg-slate-900 border border-slate-800 rounded-3xl text-sm font-mono overflow-auto max-h-[25rem] text-slate-300 whitespace-pre-wrap leading-relaxed shadow-inner">
                                            {selectedLog.payload || 'TELEMETRY_EMPTY'}
                                        </pre>
                                        <button
                                            onClick={() => navigator.clipboard.writeText(selectedLog.payload)}
                                            className="absolute top-4 right-4 p-3 bg-dark-300 border border-slate-700 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity hover:border-aegis-primary text-slate-400 hover:text-white"
                                        >
                                            <Copy size={18} />
                                        </button>
                                    </div>
                                </section>
                            </div>
                            <div className="lg:w-2/5 space-y-8 mt-10 lg:mt-0">
                                <div className="grid grid-cols-2 gap-6">
                                    <div className="p-6 bg-slate-900 border border-slate-800 rounded-3xl">
                                        <p className="text-[10px] text-slate-500 uppercase font-black mb-2 tracking-widest">Risk Level</p>
                                        <StatusChip type={selectedLog.detection_result?.severity || 'LOW'}>{selectedLog.detection_result?.severity || 'LOW'}</StatusChip>
                                    </div>
                                    <div className="p-6 bg-slate-900 border border-slate-800 rounded-3xl">
                                        <p className="text-[10px] text-slate-500 uppercase font-black mb-2 tracking-widest">Certainty</p>
                                        <p className="text-3xl font-black text-white">{(selectedLog.detection_result?.confidence * 100).toFixed(0)}%</p>
                                    </div>
                                </div>

                                <section>
                                    <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-4 block">Matched Signatures</label>
                                    <div className="space-y-3">
                                        {selectedLog.detection_result?.matched_rules?.map(rule => (
                                            <div key={rule} className="flex items-center gap-4 p-4 bg-aegis-accent/5 rounded-2xl border border-aegis-accent/20 text-xs font-bold text-slate-200">
                                                <div className="w-8 h-8 rounded-xl bg-aegis-accent/10 flex items-center justify-center text-aegis-accent">
                                                    <AlertTriangle size={18} />
                                                </div>
                                                {rule}
                                            </div>
                                        )) || (
                                                <div className="flex items-center gap-4 p-4 bg-aegis-success/5 rounded-2xl border border-aegis-success/20 text-xs font-bold text-slate-400 uppercase tracking-wider italic">
                                                    <ShieldCheck size={18} className="text-aegis-success" />
                                                    Heuristic engine validated
                                                </div>
                                            )}
                                    </div>
                                </section>

                                <div className="flex gap-4 pt-6">
                                    <button onClick={() => { navigator.clipboard.writeText(JSON.stringify(selectedLog, null, 2)) }} className="flex-1 flex items-center justify-center gap-3 bg-slate-800 p-5 rounded-2xl border border-slate-700 hover:border-aegis-primary transition-all text-xs font-black uppercase tracking-widest text-white">
                                        <Copy size={18} /> Copy JSON
                                    </button>
                                    <button className="flex-1 flex items-center justify-center gap-3 bg-aegis-accent text-white p-5 rounded-2xl shadow-xl shadow-aegis-accent/20 hover:brightness-110 transition-all text-xs font-black uppercase tracking-widest">
                                        <Shield size={18} /> Incident Ban
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

const RulesManager = ({ rules, onSaveRule, onDeleteRule }) => {
    const { Plus, Search, Edit2, Trash2, X } = lucide;
    const [search, setSearch] = useState('');
    const [editingRule, setEditingRule] = useState(null);

    const filteredRules = rules.filter(r =>
        r.name.toLowerCase().includes(search.toLowerCase()) ||
        r.category.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div className="p-10 space-y-10 animate-in fade-in h-full flex flex-col">
            <header className="flex justify-between items-end">
                <div>
                    <h2 className="text-4xl font-black text-white tracking-tighter">Ruleset Manager</h2>
                    <p className="text-slate-500 font-medium">Managing {rules.length} security signatures across the network</p>
                </div>
                <button
                    onClick={() => setEditingRule({ name: '', category: 'PromptInjection', severity: 'Medium', detection_method: 'Substring', pattern: '', enabled: true })}
                    className="flex items-center gap-3 bg-aegis-primary hover:bg-aegis-primary/80 px-8 py-4 rounded-3xl shadow-2xl shadow-aegis-primary/25 transition-all font-black uppercase text-xs tracking-widest text-white"
                >
                    <Plus size={20} /> Deploy New Signature
                </button>
            </header>

            <div className="flex-1 glass border border-slate-800 rounded-[2.5rem] overflow-hidden flex flex-col">
                <div className="p-8 border-b border-slate-800 bg-slate-900/40">
                    <div className="relative group">
                        <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-aegis-primary transition-colors" size={20} />
                        <input
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            placeholder="Identify specific patterns or categories..."
                            className="w-full bg-dark-200 border border-slate-800/50 rounded-2xl pl-14 pr-6 py-4 focus:outline-none focus:border-aegis-primary transition-all text-sm font-bold text-white shadow-inner"
                        />
                    </div>
                </div>

                <div className="overflow-auto custom-scrollbar flex-1 p-8">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        {filteredRules.slice(0, 100).map(rule => (
                            <div key={rule.name} className="p-8 bg-dark-200 border border-slate-800 rounded-[2rem] hover:border-aegis-primary hover:shadow-2xl hover:shadow-aegis-primary/5 transition-all group flex flex-col relative overflow-hidden">
                                <div className="absolute top-0 right-0 w-32 h-32 bg-aegis-primary/5 rounded-bl-full translate-x-12 -translate-y-12"></div>
                                <div className="flex justify-between items-start mb-6 relative z-10">
                                    <StatusChip type={rule.severity}>{rule.severity}</StatusChip>
                                    <div className="flex gap-2">
                                        <button onClick={() => setEditingRule(rule)} className="p-2.5 text-slate-500 hover:text-aegis-primary hover:bg-slate-800 rounded-xl transition-all"><Edit2 size={18} /></button>
                                        <button onClick={() => onDeleteRule(rule.name)} className="p-2.5 text-slate-500 hover:text-aegis-accent hover:bg-aegis-accent/10 rounded-xl transition-all"><Trash2 size={18} /></button>
                                    </div>
                                </div>
                                <h3 className="text-lg font-black text-white mb-2 truncate relative z-10">{rule.name}</h3>
                                <p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-6 relative z-10">{rule.category}</p>
                                <div className="p-5 bg-dark-300 rounded-2xl border border-white/5 font-mono text-[11px] text-aegis-primary/80 break-all h-24 overflow-hidden relative z-10 shadow-inner group-hover:text-aegis-primary transition-colors">
                                    {rule.pattern}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {editingRule && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-10 glass bg-dark-300/60 backdrop-blur-lg animate-in fade-in duration-300">
                    <div className="max-w-3xl w-full bg-dark-200 border border-white/10 rounded-[3rem] p-10 shadow-2xl animate-in zoom-in duration-500 relative">
                        <div className="flex justify-between items-center mb-10">
                            <div>
                                <h3 className="text-3xl font-black text-white tracking-tighter">Signature Deployment</h3>
                                <p className="text-slate-500 font-bold uppercase text-[10px] tracking-widest mt-1">Configuring Heuristic Pattern</p>
                            </div>
                            <button onClick={() => setEditingRule(null)} className="p-3 hover:bg-white/10 rounded-2xl transition-all text-slate-400"><X size={28} /></button>
                        </div>

                        <div className="grid grid-cols-2 gap-8 mb-10">
                            <div className="col-span-2">
                                <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 ml-1">Signature Identifier</label>
                                <input
                                    value={editingRule.name}
                                    onChange={e => setEditingRule({ ...editingRule, name: e.target.value })}
                                    placeholder="e.g. CORE_PROMPT_INJECT_V2"
                                    className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 focus:border-aegis-primary outline-none font-bold text-white shadow-inner"
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 ml-1">Asset Category</label>
                                <select
                                    value={editingRule.category}
                                    onChange={e => setEditingRule({ ...editingRule, category: e.target.value })}
                                    className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 outline-none font-bold text-white"
                                >
                                    <option>PromptInjection</option>
                                    <option>IndirectPromptInjection</option>
                                    <option>Jailbreak</option>
                                    <option>DataPoisoning</option>
                                    <option>SystemLeakage</option>
                                    <option>PIILeakage</option>
                                    <option>EncodingObfuscation</option>
                                </select>
                            </div>
                            <div>
                                <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 ml-1">Detection Logic</label>
                                <select
                                    value={editingRule.detection_method}
                                    onChange={e => setEditingRule({ ...editingRule, detection_method: e.target.value })}
                                    className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 outline-none font-bold text-white"
                                >
                                    <option>Substring</option>
                                    <option>Regex</option>
                                </select>
                            </div>
                            <div className="col-span-2">
                                <label className="block text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 ml-1">Match Pattern</label>
                                <textarea
                                    value={editingRule.pattern}
                                    onChange={e => setEditingRule({ ...editingRule, pattern: e.target.value })}
                                    placeholder="Enter string or regex pattern..."
                                    className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 h-40 font-mono text-sm outline-none focus:border-aegis-primary text-aegis-primary shadow-inner"
                                />
                            </div>
                        </div>
                        <div className="flex gap-6">
                            <button onClick={() => setEditingRule(null)} className="flex-1 bg-slate-800 p-5 rounded-2xl font-black uppercase text-xs tracking-widest text-slate-400 hover:text-white transition-all">Abort</button>
                            <button
                                onClick={() => { onSaveRule(editingRule); setEditingRule(null); }}
                                className="flex-1 bg-gradient-to-r from-aegis-primary to-aegis-secondary p-5 rounded-2xl font-black uppercase text-xs tracking-widest text-white shadow-xl shadow-aegis-primary/20"
                            >
                                Commit to Ruleset
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

const Configuration = ({ config, semanticActive, onSave }) => {
    console.log("CONFIGURATION_RENDER", { configTruthy: !!config, keys: config ? Object.keys(config) : [] });
    if (!config) return <div className="p-10 text-slate-500 font-bold">Waiting for system state...</div>;
    const { Server, Check, RefreshCw, Cpu, ExternalLink, Power, Globe, ArrowUpRight, Play } = lucide;
    const [localConfig, setLocalConfig] = useState(config);
    const [isSaving, setIsSaving] = useState(false);
    const [tunnelStatus, setTunnelStatus] = useState({ active: false, url: null });

    useEffect(() => {
        const fetchTunnel = async () => {
            const status = await API.fetch('/tunnel');
            setTunnelStatus(status);
        };
        fetchTunnel();
        const interval = setInterval(fetchTunnel, 10000);
        return () => clearInterval(interval);
    }, []);

    const updateNested = (path, value) => {
        const newCfg = { ...localConfig };
        let current = newCfg;
        const parts = path.split('.');
        for (let i = 0; i < parts.length - 1; i++) current = current[parts[i]];
        current[parts[parts.length - 1]] = value;
        setLocalConfig(newCfg);
    };

    const toggleTunnel = async () => {
        const action = tunnelStatus.active
            ? await API.fetch('/tunnel/stop', { method: 'POST' })
            : await API.fetch('/tunnel/start', { method: 'POST' });

        if (action && typeof action.active === 'boolean') {
            setTunnelStatus({ active: !!action.active, url: action.url || null });
        } else {
            const status = await API.fetch('/tunnel');
            setTunnelStatus(status);
        }
    };

    return (
        <div className="p-10 space-y-10 animate-in slide-in-from-bottom-5 overflow-y-auto max-h-screen custom-scrollbar pb-32">
            <header className="flex justify-between items-end">
                <div>
                    <h2 className="text-4xl font-black text-white tracking-tighter">Proxy Optimization</h2>
                    <p className="text-slate-500 font-medium">Fine-tuning the core Aegis.rs protection layer</p>
                </div>
                <button
                    onClick={async () => { setIsSaving(true); await onSave(localConfig); setIsSaving(false); }}
                    className="flex items-center gap-3 bg-aegis-success hover:bg-aegis-success/80 px-10 py-4 rounded-3xl shadow-2xl shadow-aegis-success/25 transition-all font-black uppercase text-xs tracking-[0.2em] text-white"
                >
                    {isSaving ? <RefreshCw className="animate-spin" size={20} /> : <Check size={20} />}
                    Sync System State
                </button>
            </header>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-10">
                <div className="glass p-10 rounded-[2.5rem] border border-slate-800">
                    <div className="flex items-center gap-4 mb-10">
                        <div className="p-4 bg-aegis-primary/10 rounded-2xl"><Server className="text-aegis-primary" size={24} /></div>
                        <h3 className="text-2xl font-black text-white">Upstream Routing</h3>
                    </div>
                    <div className="space-y-8">
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3 block ml-1">Primary LLM Gateway</label>
                            <input
                                value={localConfig.proxy.target_url}
                                onChange={e => updateNested('proxy.target_url', e.target.value)}
                                className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 focus:border-aegis-primary outline-none font-bold text-white shadow-inner"
                            />
                        </div>
                        <div className="grid grid-cols-2 gap-8">
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3 block ml-1">Ingestion Limit (KB)</label>
                                <input
                                    type="number"
                                    value={localConfig.proxy.max_body_size_bytes / 1024}
                                    onChange={e => updateNested('proxy.max_body_size_bytes', parseInt(e.target.value) * 1024)}
                                    className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 focus:border-aegis-primary outline-none font-bold text-white shadow-inner"
                                />
                            </div>
                            <div>
                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3 block ml-1">Response TTL (ms)</label>
                                <input
                                    type="number"
                                    value={localConfig.proxy.read_timeout_ms}
                                    onChange={e => updateNested('proxy.read_timeout_ms', parseInt(e.target.value))}
                                    className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 focus:border-aegis-primary outline-none font-bold text-white shadow-inner"
                                />
                            </div>
                        </div>
                    </div>
                </div>

                <div className="glass p-10 rounded-[2.5rem] border border-slate-800 relative overflow-hidden group">
                    <div className="absolute top-0 right-0 p-8 transform rotate-1 group-hover:rotate-0 transition-transform">
                        <img src="https://groq.com/wp-content/uploads/2024/03/Groq_Logo_RGB_White.png" alt="Groq" className="h-4 opacity-30 group-hover:opacity-100 transition-opacity" />
                    </div>
                    <div className="flex items-center gap-4 mb-10">
                        <div className="p-4 bg-aegis-secondary/10 rounded-2xl"><Cpu className="text-aegis-secondary" size={24} /></div>
                        <h3 className="text-2xl font-black text-white">Semantic AI Judge</h3>
                        <div className="ml-auto">
                            {semanticActive ? (
                                <span className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-green-500/10 border border-green-500/20 text-green-500 text-[10px] font-black uppercase tracking-widest animate-pulse">
                                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full shadow-[0_0_8px_rgba(34,197,94,0.6)]"></div>
                                    Active
                                </span>
                            ) : (
                                <span className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-yellow-500 text-[10px] font-black uppercase tracking-widest">
                                    <div className="w-1.5 h-1.5 bg-yellow-500 rounded-full"></div>
                                    Heuristic Only
                                </span>
                            )}
                        </div>
                    </div>
                    <div className="space-y-8">
                        <div className="bg-gradient-to-br from-aegis-secondary/10 to-transparent border border-aegis-secondary/20 rounded-3xl p-6 relative overflow-hidden">
                            <p className="text-xs text-slate-300 mb-4 font-bold relative z-10">Leverage ultra-fast LPU™ inference to validate ambiguous heuristic matches.</p>
                            <a href="https://console.groq.com/keys" target="_blank" className="text-aegis-secondary font-black text-[10px] uppercase tracking-widest flex items-center gap-2 hover:brightness-125 relative z-10">
                                Provision Logic Key <ExternalLink size={14} />
                            </a>
                            <div className="absolute bottom-[-20%] right-[-10%] w-32 h-32 bg-aegis-secondary/5 rounded-full blur-2xl"></div>
                        </div>
                        <div>
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em] mb-3 block ml-1">Inference Engine Key</label>
                            <input
                                type="password"
                                value={localConfig.ai_judge.api_key}
                                onChange={e => updateNested('ai_judge.api_key', e.target.value)}
                                placeholder="gsk_••••••••••••••••••••••••"
                                className="w-full bg-slate-900 border border-slate-800 rounded-2xl px-6 py-4 focus:border-aegis-secondary outline-none font-mono text-sm text-white shadow-inner"
                            />
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <button
                                onClick={() => updateNested('detection.heuristic_only_mode', !localConfig.detection.heuristic_only_mode)}
                                className={`p-4 rounded-2xl border font-bold text-[10px] uppercase tracking-widest transition-all ${localConfig.detection.heuristic_only_mode
                                        ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500'
                                        : 'bg-aegis-secondary/10 border-aegis-secondary/20 text-aegis-secondary'
                                    }`}
                            >
                                {localConfig.detection.heuristic_only_mode ? 'Heuristic Only: ON' : 'Heuristic Only: OFF'}
                            </button>
                            <button
                                onClick={() => updateNested('detection.all_requests_ai_judge', !localConfig.detection.all_requests_ai_judge)}
                                className={`p-4 rounded-2xl border font-bold text-[10px] uppercase tracking-widest transition-all ${localConfig.detection.all_requests_ai_judge
                                        ? 'bg-aegis-primary/10 border-aegis-primary/20 text-aegis-primary'
                                        : 'bg-slate-800 border-slate-700 text-slate-500'
                                    }`}
                                disabled={!localConfig.ai_judge.api_key}
                            >
                                {localConfig.detection.all_requests_ai_judge ? 'Deep Analysis: ON' : 'Deep Analysis: OFF'}
                            </button>
                        </div>
                    </div>
                </div>

                <div className="glass p-10 rounded-[2.5rem] border border-slate-800 overflow-hidden group relative">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-aegis-primary via-aegis-secondary to-aegis-primary"></div>
                    <div className="flex justify-between items-center mb-10">
                        <div className="flex items-center gap-4">
                            <div className="p-4 bg-slate-800 rounded-2xl group-hover:bg-aegis-primary/10 transition-colors"><Globe className="text-slate-400 group-hover:text-aegis-primary" size={24} /></div>
                            <h3 className="text-2xl font-black text-white">Public Uplink</h3>
                        </div>
                        <StatusChip type={tunnelStatus.active ? 'safe' : 'info'}>{tunnelStatus.active ? 'Live' : 'Offline'}</StatusChip>
                    </div>
                    <div className="space-y-8 relative z-10 flex-1 flex flex-col">
                        <p className="text-sm text-slate-500 font-medium">Expose your local proxy dashboard through a Serveo HTTPS tunnel over SSH. Optionally set a custom subdomain in tunnel config.</p>

                        <div className="flex-1 p-8 bg-slate-900/50 rounded-[2rem] border-2 border-dashed border-slate-800 flex flex-col items-center justify-center space-y-6 group-hover:border-aegis-primary/30 transition-all">
                            {tunnelStatus.active ? (
                                <>
                                    <div className="text-center">
                                        <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">Public Endpoint</p>
                                        <a href={tunnelStatus.url} target="_blank" className="text-lg font-black text-aegis-primary flex items-center gap-2 hover:underline">
                                            {tunnelStatus.url} <ArrowUpRight size={20} />
                                        </a>
                                    </div>
                                    <button onClick={toggleTunnel} className="flex items-center gap-3 bg-aegis-accent hover:brightness-110 px-8 py-4 rounded-2xl font-black uppercase text-xs tracking-widest text-white transition-all shadow-xl shadow-aegis-accent/20">
                                        <Power size={18} /> Kill Uplink
                                    </button>
                                </>
                            ) : (
                                <>
                                    <div className="w-20 h-20 rounded-full bg-slate-800 flex items-center justify-center text-slate-600">
                                        <Globe size={40} />
                                    </div>
                                    <button onClick={toggleTunnel} className="flex items-center gap-3 bg-aegis-primary hover:brightness-110 px-10 py-5 rounded-2xl font-black uppercase text-xs tracking-widest text-white transition-all shadow-2xl shadow-aegis-primary/30">
                                        <Play size={20} /> Initialize Tunnel
                                    </button>
                                </>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const App = () => {
    const [page, setPage] = useState('command');
    const [stats, setStats] = useState({});
    const [logs, setLogs] = useState([]);
    const [rules, setRules] = useState([]);
    const [config, setConfig] = useState(null);
    const [semanticActive, setSemanticActive] = useState(false);
    const [auth, setAuth] = useState(null);

    useEffect(() => {
        const checkAuth = async () => {
            const status = await API.fetch('/auth/status');
            setAuth(status.authenticated);
        };
        checkAuth();
    }, []);

    useEffect(() => {
        if (!auth) return;
        const fetchData = async () => {
            try {
                const [s, l, r, c] = await Promise.all([
                    API.fetch('/stats'),
                    API.fetch('/logs'),
                    API.fetch('/rules'),
                    API.fetch('/config')
                ]);
                if (s && typeof s === 'object') setStats(s);
                if (Array.isArray(l)) setLogs([...l].reverse());
                if (s && typeof s === 'object') setStats(s);
                if (Array.isArray(l)) setLogs([...l].reverse());
                if (Array.isArray(r)) setRules(r);

                if (c) {
                    const actualConfig = c.config || c;
                    console.log("FETCHED_CONFIG", { isNested: !!c.config, data: actualConfig });
                    setConfig(actualConfig);
                    if (c.semantic_active !== undefined) setSemanticActive(c.semantic_active);
                }
            } catch (err) {
                console.error("AEGIS_FETCH_ERROR:", err);
            }
        };
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, [auth]);

    const handleLogout = async () => {
        await API.fetch('/auth/logout', { method: 'POST' });
        window.location.reload();
    };

    const handleSaveRule = async (rule) => {
        await API.fetch('/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rule)
        });
        const r = await API.fetch('/rules');
        setRules(r);
    };

    const handleDeleteRule = async (name) => {
        await API.fetch(`/rules?name=${name}`, { method: 'DELETE' });
        const r = await API.fetch('/rules');
        setRules(r);
    };

    const handleSaveConfig = async (newCfg) => {
        await API.fetch('/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newCfg)
        });
        setConfig(newCfg);
    };

    const handleExport = (format) => {
        const content = format === 'json' ? JSON.stringify(logs, null, 2) :
            "timestamp,verdict,ip,reasoning\n" + logs.map(l => `${l.timestamp},${l.verdict},${l.meta?.ip || ''},${l.detection_result?.reasoning}`).join('\n');
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `aegis_export_${new Date().getTime()}.${format}`;
        a.click();
    };

    if (auth === null) return <div className="min-h-screen bg-dark-300 flex items-center justify-center"><div className="w-10 h-10 border-4 border-aegis-primary border-t-transparent rounded-full animate-spin"></div></div>;
    if (!auth) return <LoginPanel onLogin={() => setAuth(true)} />;

    return (
        <div className="flex h-screen bg-dark-300 text-slate-200 font-sans selection:bg-aegis-primary/30 selection:text-aegis-primary overflow-hidden">
            <Sidebar activePage={page} setActivePage={setPage} onLogout={handleLogout} />
            <main className="flex-1 relative overflow-hidden flex flex-col">
                <div className="absolute top-0 left-0 w-full h-32 bg-gradient-to-b from-aegis-primary/5 to-transparent pointer-events-none"></div>
                {page === 'command' && <CommandCenter stats={stats} logs={logs} nodeLabel={stats.node_label} />}
                {page === 'analytics' && <Analytics logs={logs} stats={stats} />}
                {page === 'logs' && <AttackLogs logs={logs} onExport={handleExport} />}
                {page === 'rules' && <RulesManager rules={rules} onSaveRule={handleSaveRule} onDeleteRule={handleDeleteRule} />}
                {page === 'config' && config && <Configuration config={config} semanticActive={semanticActive} onSave={handleSaveConfig} />}
            </main>
        </div>
    );
};

// --- Bootstrap ---
const init = () => {
    console.log("Aegis Dashboard: Initializing Core...");
    const container = document.getElementById('root');
    if (!container) {
        console.error("Aegis Error: #root mount point not found.");
        return;
    }
    const aegisRoot = ReactDOM.createRoot(container);
    window._aegisRoot = aegisRoot; // For debugging only
    aegisRoot.render(React.createElement(App));
    console.log("Aegis Dashboard: Uplink Established.");
};

if (document.readyState === 'complete') {
    init();
} else {
    window.addEventListener('load', init);
}
