/**
 * Kenosian Vault 조회 클라이언트 — 정리가 커널을 통과했는지 물어본다.
 *
 *   import { Vault } from "@kenosian/vault";
 *   const v = new Vault();
 *   const c = await v.theorem("KLean.Atoms.Bio.BiologicalAgeAtom.weighted_sum_nonneg");
 *   console.log(c.verified, c.axiom_level);      // true  kernel-standard
 *
 * ★Lean 툴체인을 번들하지 않는다. 이건 HTTP 클라이언트이고 native `fetch` 만 쓴다.
 *   의존성 0 — Node 18+, Cloudflare Workers, Vercel Edge, Deno, 브라우저에서 그대로 동작한다.
 */

const DEFAULT_BASE = "https://kpp.kenosian.com";
const UA = "kenosian-vault-ts";

/** 조회 실패. ⛔이유를 삼키지 않는다 — 조용한 강등이 제일 나쁘다. */
export class VaultError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "VaultError";
  }
}

/** 서빙 커밋이 기대한 커밋과 다르다. 감사 중이라면 여기서 멈춰야 한다. */
export class StaleVaultError extends VaultError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "StaleVaultError";
  }
}

/**
 * 정리 하나의 검증서.
 *
 * ⛔`verified` 는 `true`/`false` 가 아니라 **`true`/`null`** 이다.
 *   `.olean` 이 그 커밋에 없으면 "모른다"이지 "거짓"이 아니다.
 *   이 구분을 없애면 근거 없이 true 를 파는 것과 같아진다(2026-08-08 규칙).
 */
export interface Certificate {
  readonly fqn: string;
  readonly verified: boolean | null;
  readonly axiom_level: string | null;
  readonly olean_sha256: string | null;
  readonly module: string | null;
  readonly path: string | null;
  readonly claim: string | null;
  readonly quarantined: boolean;
  readonly statement: string | null;
  readonly refs: readonly string[];
  readonly topics: readonly string[];
  readonly depends_on: readonly string[];
  readonly used_by: readonly string[];
  readonly compute: string | null;
  readonly seal: Readonly<Record<string, unknown>> | null;
  readonly commit: string;
  /** 표준 공리만 쓰는가. `native_decide` 가 섞이면 compiler-trusted 로 강등된다. */
  readonly kernelStandard: boolean;
}

function certificateFromJson(d: Record<string, unknown>): Certificate {
  const axiomLevel = (d["axiom_level"] as string | undefined) ?? null;
  return Object.freeze({
    fqn: d["fqn"] as string,
    verified: (d["verified"] as boolean | null | undefined) ?? null,
    axiom_level: axiomLevel,
    olean_sha256: (d["olean_sha256"] as string | undefined) ?? null,
    module: (d["module"] as string | undefined) ?? null,
    path: (d["path"] as string | undefined) ?? null,
    claim: (d["claim"] as string | undefined) ?? null,
    quarantined: Boolean(d["quarantined"] ?? false),
    statement: (d["statement"] as string | undefined) ?? null,
    refs: [...((d["refs"] as string[] | undefined) ?? [])],
    topics: [...((d["topics"] as string[] | undefined) ?? [])],
    depends_on: [...((d["depends_on"] as string[] | undefined) ?? [])],
    used_by: [...((d["used_by"] as string[] | undefined) ?? [])],
    compute: (d["compute"] as string | undefined) ?? null,
    seal: (d["seal"] as Record<string, unknown> | undefined) ?? null,
    commit: (d["commit"] as string | undefined) ?? "",
    kernelStandard: axiomLevel === "kernel-standard",
  });
}

export interface VaultOptions {
  /** 기본값 https://kpp.kenosian.com */
  base?: string;
  /** 밀리초. 기본값 10000. */
  timeoutMs?: number;
  /** 주면 서빙이 그 커밋이 아닐 때 StaleVaultError 를 던진다. */
  expectCommit?: string;
}

/**
 * `kpp.kenosian.com/v1/klv/*` 를 부르는 얇은 클라이언트.
 *
 * expectCommit 을 주면 서빙이 그 커밋이 아닐 때 StaleVaultError 를 던진다.
 * 감사자가 특정 시점을 검증할 때 쓴다 — 서버가 그새 앞서가면 조용히 다른 답을 받게 되므로.
 */
export class Vault {
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly expectCommit: string | undefined;

  constructor(options: VaultOptions = {}) {
    this.base = (options.base ?? DEFAULT_BASE).replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.expectCommit = options.expectCommit;
  }

  // ── 내부 ────────────────────────────────────────────────────────────
  private async get(path: string): Promise<{ body: Record<string, unknown>; served: string }> {
    const url = `${this.base}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(url, {
        headers: { "User-Agent": UA, Accept: "application/json" },
        signal: controller.signal,
      });
    } catch (e) {
      throw new VaultError(`연결 실패 ${url}: ${(e as Error).message}`, { cause: e });
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      if (response.status === 404) {
        throw new VaultError(`금고에 없다: ${path}`);
      }
      throw new VaultError(`HTTP ${response.status} — ${url}`);
    }

    const served = response.headers.get("X-KLV-Commit-Hash") ?? "";

    let body: Record<string, unknown>;
    try {
      body = (await response.json()) as Record<string, unknown>;
    } catch (e) {
      throw new VaultError(`JSON 아님 ${url}: ${(e as Error).message}`, { cause: e });
    }

    if (this.expectCommit && served && served !== this.expectCommit) {
      throw new StaleVaultError(
        `서빙 커밋 ${served} != 기대 ${this.expectCommit}. ` +
          "금고가 앞서갔다 — 같은 시점을 보려면 manifest 를 쓰거나 expectCommit 을 갱신해라."
      );
    }

    return { body, served };
  }

  // ── 공개 API ────────────────────────────────────────────────────────
  /** 정리 하나의 검증서. 없으면 VaultError. */
  async theorem(fqn: string): Promise<Certificate> {
    const { body } = await this.get(`/v1/klv/theorem/${encodeURIComponent(fqn)}`);
    return certificateFromJson(body);
  }

  /**
   * `theorem()`의 별칭. ⛔이름이 실시간 검증처럼 들리지만 그렇지 않다 —
   * 이 호출도 HTTP GET 하나뿐이다. 커널은 CI에서 이미 돌았고, 여기서는
   * 그 판정을 O(1)로 조회할 뿐이다(2코어 서버에서 요청마다 커널을 돌리는
   * 설계는 8/9에 DoS·5.15초 지연 이유로 기각됨). 호출부에서 "검증한다"는
   * 직관적인 이름을 쓰고 싶을 때 이걸 부른다.
   */
  async verify(fqn: string): Promise<Certificate> {
    return this.theorem(fqn);
  }

  /** 금고 집계와 서빙 커밋. */
  async stats(): Promise<Record<string, unknown>> {
    const { body } = await this.get("/v1/klv/stats");
    return body;
  }

  /**
   * 이 모듈이 바뀌면 다시 봐야 하는 모듈들 (역방향 DAG).
   *
   * 빈 목록은 "잎 모듈"이라는 뜻이지 "없다"는 뜻이 아니다 — 없으면 VaultError 가 난다.
   */
  async impact(module: string): Promise<string[]> {
    const { body } = await this.get(`/v1/klv/impact/${encodeURIComponent(module)}`);
    return [...((body["dependents"] as string[] | undefined) ?? [])];
  }

  /** 지금 서빙 중인 금고 커밋. */
  async servedCommit(): Promise<string> {
    const s = await this.stats();
    return String(s["commit"] ?? "");
  }
}
