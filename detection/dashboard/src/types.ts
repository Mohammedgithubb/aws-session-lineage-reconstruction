export type Slim = { key: string; identity: string; state: string; level: number; bel: number; first: number; last: number; n: number; methods_fired: string[]; net: string; uaf: string };
export type Alert = { t: number; key: string; identity: string; state: string; bel: number; methods: string[]; why: string[]; sealed?: string; response?: string };
export type Summary = { mode: string; live: boolean; events: number; learned: number; sessions: number; uptime: number;
  counts: Record<string, number>; jobs: null | { S2: string; S3: string; coverage: Record<string, number>; global_coverage: number };
  top: Slim[]; alerts: Alert[]; recent: { time: string; identity: string; token: string; net: string; uaf: string; error: string | null; key: string }[] };
export type Ev = { id: string; t: number; time: string; token: string; net: string; ip: string; uaf: string; error: string | null; region: string; resources: string[] };
export type Session = Slim & { issuer: string; mass: Record<string, number>; z: Record<string, number>; reasons: Record<string, string[]>;
  history: [number, number][]; sealed: string | null; response: string | null; m_S: number; events: Ev[] };
