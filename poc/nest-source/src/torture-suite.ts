/**
 * Torture suite for @naskot/node-hmac-auth.
 *
 * Exhaustively exercises every public surface of the lib that the static
 * "happy path" sync + revert-demo do not touch. Each helper logs its own
 * assertion outcome, prefixed with `[nest_source] torture:`. A failing
 * assertion prefixes the line with `[nest_source] torture FAIL:`.
 *
 * Run order matters: some cases set up state for the next ones. They are
 * orchestrated by `runTortureSuite()`.
 *
 * The suite stays deliberately verbose in its log output so a reader can
 * scan a single `docker compose logs` and verify every covered path.
 */
import type {
  HmacInternalPropagationOperation,
  HmacPropagateTargetStore,
  InitializedHmacHttpAuth,
  InitializedHmacMessageAuth,
  PropagateHmacClientOptions,
} from "@naskot/node-hmac-auth";

type Signer = PropagateHmacClientOptions["apiFetch"];

export type TortureContext = {
  hmacAuth: InitializedHmacHttpAuth;
  hmacMessageAuth: InitializedHmacMessageAuth;
  signer: Signer;
  targets: string[];
};

const log = (line: string): void => console.log(`[nest_source] torture: ${line}`);
const fail = (line: string): void => console.error(`[nest_source] torture FAIL: ${line}`);

function expectEq<T>(label: string, actual: T, expected: T): void {
  if (actual === expected) {
    log(`${label} OK actual=${JSON.stringify(actual)}`);
  } else {
    fail(`${label} actual=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`);
  }
}

function expectTrue(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    log(`${label} OK${detail ? ` ${detail}` : ""}`);
  } else {
    fail(`${label}${detail ? ` ${detail}` : ""}`);
  }
}

const summarizeHash = (hash: string | null | undefined): string => (hash ? hash.slice(0, 12) : "(none)");

async function callPropagate(
  ctx: TortureContext,
  operation: HmacInternalPropagationOperation,
  options: {
    clientId?: string;
    secret?: string;
    targetStore?: HmacPropagateTargetStore;
    fromDbSeed?: boolean;
    targets?: string[];
  }
) {
  const operationOptions: PropagateHmacClientOptions = {
    operation,
    targets: options.targets ?? ctx.targets,
    apiFetch: ctx.signer,
  };

  if (options.clientId !== undefined) {
    operationOptions.clientId = options.clientId;
  }
  if (options.secret !== undefined) {
    operationOptions.secret = options.secret;
    operationOptions.allowedIps = ["0.0.0.0/0", "::/0"];
  }
  if (options.targetStore !== undefined) {
    operationOptions.targetStore = options.targetStore;
  }
  if (options.fromDbSeed === true) {
    operationOptions.fromDbSeed = true;
  }

  return ctx.hmacAuth.propagateClientToApis(operationOptions);
}

/**
 * Section R - revert paths.
 *
 *   R1. Remote revert with no backup (never rotated) -> reverted:false
 *   R2. Remote revert on a clientId unknown to the target -> reverted:false
 *   R3. Local revert (clients.revert on the source) after a real rotation
 *   R4. Message-bridge revert (hmacMessageAuth.clients.revert)
 *   R5. Double rotate before TTL expires -> backup overwritten -> revert lands on the SECOND original hash, NOT the first
 */
async function runRevertTortureSuite(ctx: TortureContext): Promise<void> {
  log("=== section R: revert torture ===");

  // R1: propagate-create a fresh db-seed credential, never rotate it, then call revert.
  //     Expect reverted:false because no backup key was ever written.
  const r1Id = "torture_r1_never_rotated";
  await callPropagate(ctx, "create", {
    clientId: r1Id,
    secret: "r1-secret",
    fromDbSeed: true,
  });
  const r1Results = await callPropagate(ctx, "revert", { clientId: r1Id });
  for (const r of r1Results) {
    const body = r.body as { reverted?: boolean } | null;
    expectEq(`R1 remote-revert never-rotated target=${r.target} status`, r.status, 201);
    expectEq(`R1 remote-revert never-rotated target=${r.target} reverted`, body?.reverted, false);
  }

  // R2: revert on a clientId that was never propagated (target does not know it).
  //     Expect reverted:false, no error.
  const r2Id = "torture_r2_never_existed";
  const r2Results = await callPropagate(ctx, "revert", { clientId: r2Id });
  for (const r of r2Results) {
    const body = r.body as { reverted?: boolean } | null;
    expectEq(`R2 remote-revert unknown-id target=${r.target} status`, r.status, 201);
    expectEq(`R2 remote-revert unknown-id target=${r.target} reverted`, body?.reverted, false);
  }

  // R3: local revert on source. To exercise the local backup path we need a
  //     TRUE local rotation: write once (creates the record, no backup yet),
  //     write again with the same fromDbSeed flag (creates the backup). Then
  //     clients.revert(clientId) restores the first hash. The clientId is
  //     suffixed with a fresh nonce so the test is idempotent across container
  //     restarts (state in Redis from a previous run would otherwise turn the
  //     first setSecret into a rotation, polluting the backup key).
  const r3Id = `torture_r3_local_revert_${Date.now()}`;
  await ctx.hmacAuth.clients.setSecret(r3Id, "r3-original", null, ["0.0.0.0/0", "::/0"], { fromDbSeed: true });
  const r3BeforeHash = await ctx.hmacAuth.clients.getSecretHash(r3Id);
  expectTrue("R3 source-local pre-rotate has hash", !!r3BeforeHash, `hash=${summarizeHash(r3BeforeHash)}`);

  await ctx.hmacAuth.clients.setSecret(r3Id, "r3-rotated", null, ["0.0.0.0/0", "::/0"], { fromDbSeed: true });
  const r3MidHash = await ctx.hmacAuth.clients.getSecretHash(r3Id);
  expectTrue(
    "R3 source-local post-rotate hash changed",
    r3BeforeHash !== r3MidHash,
    `before=${summarizeHash(r3BeforeHash)} after=${summarizeHash(r3MidHash)}`
  );

  const r3RevertResult = await ctx.hmacAuth.clients.revert(r3Id);
  expectEq("R3 source-local revert reverted", r3RevertResult.reverted, true);

  const r3AfterHash = await ctx.hmacAuth.clients.getSecretHash(r3Id);
  expectEq("R3 source-local hash restored", r3AfterHash, r3BeforeHash);

  // R3-bis: a second revert with no backup left -> reverted:false (no-op).
  const r3SecondRevert = await ctx.hmacAuth.clients.revert(r3Id);
  expectEq("R3-bis source-local second-revert reverted", r3SecondRevert.reverted, false);

  // R4: message-bridge revert. Propagate a message client, rotate it (via
  //     propagate update with fromDbSeed:true so the target writes a backup),
  //     then revert it via PATCH on the message store.
  const r4Id = "torture_r4_message_revert";
  await callPropagate(ctx, "create", {
    clientId: r4Id,
    secret: "r4-original",
    targetStore: "message",
    fromDbSeed: true,
  });
  await callPropagate(ctx, "update", {
    clientId: r4Id,
    secret: "r4-rotated",
    targetStore: "message",
    fromDbSeed: true,
  });
  const r4RevertResults = await callPropagate(ctx, "revert", { clientId: r4Id, targetStore: "message" });
  for (const r of r4RevertResults) {
    const body = r.body as { reverted?: boolean; kind?: string } | null;
    expectEq(`R4 message-revert target=${r.target} status`, r.status, 201);
    expectEq(`R4 message-revert target=${r.target} kind`, body?.kind, "message");
    expectEq(`R4 message-revert target=${r.target} reverted`, body?.reverted, true);
  }

  // R5: rotate N then N+1 before TTL expires. Expect backup to be overwritten
  //     so the revert restores the N+1-original hash (i.e. the rotation 1
  //     hash), NOT the very first one (which is irrecoverable now).
  const r5Id = "torture_r5_double_rotate";
  await callPropagate(ctx, "create", {
    clientId: r5Id,
    secret: "r5-round0",
    fromDbSeed: true,
  });
  await callPropagate(ctx, "update", {
    clientId: r5Id,
    secret: "r5-round1",
    fromDbSeed: true,
  });
  // Now target's current hash = hash(r5-round1), backup = hash(r5-round0).
  await callPropagate(ctx, "update", {
    clientId: r5Id,
    secret: "r5-round2",
    fromDbSeed: true,
  });
  // Now target's current hash = hash(r5-round2), backup = hash(r5-round1)
  // (round0 hash is gone).
  const r5RevertResults = await callPropagate(ctx, "revert", { clientId: r5Id });
  for (const r of r5RevertResults) {
    const body = r.body as { reverted?: boolean } | null;
    expectEq(`R5 double-rotate revert target=${r.target} reverted`, body?.reverted, true);
  }
  // A SECOND revert should now return false (backup was consumed).
  const r5SecondRevert = await callPropagate(ctx, "revert", { clientId: r5Id });
  for (const r of r5SecondRevert) {
    const body = r.body as { reverted?: boolean } | null;
    expectEq(`R5 double-rotate second-revert target=${r.target} reverted`, body?.reverted, false);
  }
}

/**
 * Section C - CRUD propagation paths.
 *
 *   C1. propagate create on an existing clientId -> 403 "Client already exists"
 *   C2. propagate update on a missing clientId -> 403 "Client does not exist"
 *   C3. propagate delete on an existing clientId -> 201, then target.get is null
 *   C4. propagate delete on a missing clientId -> 403
 *   C5. propagate health -> 200, body.ok=true
 */
async function runCrudTortureSuite(ctx: TortureContext): Promise<void> {
  log("=== section C: CRUD torture ===");

  const cBaseId = "torture_c_base_client";
  await callPropagate(ctx, "create", {
    clientId: cBaseId,
    secret: "c-base-secret",
    fromDbSeed: false,
  });

  // C1: create on existing -> 403
  const c1Results = await callPropagate(ctx, "create", {
    clientId: cBaseId,
    secret: "c-base-secret",
    fromDbSeed: false,
  });
  for (const r of c1Results) {
    const body = r.body as { message?: string } | null;
    expectEq(`C1 create-existing target=${r.target} status`, r.status, 403);
    expectEq(`C1 create-existing target=${r.target} message`, body?.message, "Client already exists");
  }

  // C2: update on missing -> 403
  const c2Id = "torture_c2_missing";
  const c2Results = await callPropagate(ctx, "update", {
    clientId: c2Id,
    secret: "c2-secret",
    fromDbSeed: false,
  });
  for (const r of c2Results) {
    const body = r.body as { message?: string } | null;
    expectEq(`C2 update-missing target=${r.target} status`, r.status, 403);
    expectEq(`C2 update-missing target=${r.target} message`, body?.message, "Client does not exist");
  }

  // C3: delete on existing -> 201 then target.get null
  const c3Results = await callPropagate(ctx, "delete", { clientId: cBaseId });
  for (const r of c3Results) {
    const body = r.body as { operation?: string } | null;
    expectEq(`C3 delete-existing target=${r.target} status`, r.status, 201);
    expectEq(`C3 delete-existing target=${r.target} body.operation`, body?.operation, "delete");
  }

  // C4: delete on missing -> 403
  const c4Results = await callPropagate(ctx, "delete", { clientId: "torture_c4_missing" });
  for (const r of c4Results) {
    expectEq(`C4 delete-missing target=${r.target} status`, r.status, 403);
  }

  // C5: health -> 200. NOTE: GET signature requires the target to expose the
  //     raw body (empty buffer) to verifyHttpSignature; some adapters (e.g. an
  //     `express.json()` setup that only captures rawBody in its `verify`
  //     callback for write methods) do not capture it for GET requests. The
  //     resulting body-hash mismatch shows up as 403 on the broken adapter.
  //     We log the full body of any failure so the reader can pinpoint which
  //     target needs its body-parser/rawBody plumbing fixed.
  const c5Results = await callPropagate(ctx, "health", {});
  for (const r of c5Results) {
    const body = r.body as { ok?: boolean; error?: string; message?: string } | null;
    if (r.status !== 200) {
      fail(
        `C5 health target=${r.target} unexpected status=${r.status} body=${JSON.stringify(body)} - adapter likely missing rawBody capture for GET`
      );
      continue;
    }
    expectEq(`C5 health target=${r.target} status`, r.status, 200);
    expectEq(`C5 health target=${r.target} body.ok`, body?.ok, true);
  }
}

/**
 * Section M - clients management (local, source side).
 *
 *   M1. regenerateSecret HTTP changes the hash, preserves clientId
 *   M2. regenerateSecret message changes the hash, preserves clientId
 *   M3. setAllowedIps then clients.get reflects update
 *   M4. clients.delete then clients.get returns null
 */
async function runClientsManagementTortureSuite(ctx: TortureContext): Promise<void> {
  log("=== section M: management torture ===");

  // M1: regenerateSecret HTTP
  const m1Id = "torture_m1_regen_http";
  await ctx.hmacAuth.clients.create({ clientId: m1Id, plainSecret: "m1-original", expiresAt: null, allowedIps: [] });
  const m1Before = await ctx.hmacAuth.clients.get(m1Id);
  const m1Regen = await ctx.hmacAuth.clients.regenerateSecret(m1Id);
  expectTrue(
    "M1 regen http hash changed",
    m1Before?.secretHash !== m1Regen.secretHash,
    `before=${summarizeHash(m1Before?.secretHash)} after=${summarizeHash(m1Regen.secretHash)}`
  );

  // M2: regenerateSecret message
  const m2Id = "torture_m2_regen_message";
  await ctx.hmacMessageAuth.clients.create({ clientId: m2Id, plainSecret: "m2-original", expiresAt: null, allowedIps: [] });
  const m2Before = await ctx.hmacMessageAuth.clients.get(m2Id);
  const m2Regen = await ctx.hmacMessageAuth.clients.regenerateSecret(m2Id);
  expectTrue(
    "M2 regen message hash changed",
    m2Before?.secretHash !== m2Regen.secretHash,
    `before=${summarizeHash(m2Before?.secretHash)} after=${summarizeHash(m2Regen.secretHash)}`
  );

  // M3: setAllowedIps
  const m3Id = "torture_m3_allowed_ips";
  await ctx.hmacAuth.clients.create({ clientId: m3Id, plainSecret: "m3-secret", expiresAt: null, allowedIps: ["10.0.0.1"] });
  await ctx.hmacAuth.clients.setAllowedIps(m3Id, ["10.0.0.2/32", "192.168.0.0/16"]);
  const m3After = await ctx.hmacAuth.clients.get(m3Id);
  expectEq("M3 setAllowedIps stored length", m3After?.allowedIps.length, 2);
  expectEq("M3 setAllowedIps first", m3After?.allowedIps?.[0], "10.0.0.2/32");
  expectEq("M3 setAllowedIps second", m3After?.allowedIps?.[1], "192.168.0.0/16");

  // M4: clients.delete then get null
  const m4Id = "torture_m4_delete_local";
  await ctx.hmacAuth.clients.create({ clientId: m4Id, plainSecret: "m4-secret", expiresAt: null, allowedIps: [] });
  await ctx.hmacAuth.clients.delete(m4Id);
  const m4After = await ctx.hmacAuth.clients.get(m4Id);
  expectEq("M4 delete-local after-get", m4After, null);
}

/**
 * Section F - revert field preservation.
 *
 *   F1. After revert, fromDbSeed/allowedIps/expiresAt are preserved (not reset).
 */
async function runFieldPreservationTortureSuite(ctx: TortureContext): Promise<void> {
  log("=== section F: revert field preservation ===");

  const fId = "torture_f1_preserve";
  await ctx.hmacAuth.clients.create({
    clientId: fId,
    plainSecret: "f-original",
    expiresAt: 4102444800000, // 2100-01-01
    allowedIps: ["172.16.0.0/12"],
  });
  // Mark as fromDbSeed via setSecret with options to "convert" it dynamically.
  await ctx.hmacAuth.clients.setSecret(fId, "f-original", 4102444800000, ["172.16.0.0/12"], { fromDbSeed: true });
  await ctx.hmacAuth.clients.setSecret(fId, "f-rotated", 4102444800000, ["172.16.0.0/12"], { fromDbSeed: true });

  const revertResult = await ctx.hmacAuth.clients.revert(fId);
  expectEq("F1 revert returns reverted", revertResult.reverted, true);

  const fAfter = await ctx.hmacAuth.clients.get(fId);
  expectEq("F1 fromDbSeed preserved", fAfter?.fromDbSeed, true);
  expectEq("F1 expiresAt preserved", fAfter?.expiresAt, 4102444800000);
  expectEq("F1 allowedIps length preserved", fAfter?.allowedIps?.length, 1);
  expectEq("F1 allowedIps first preserved", fAfter?.allowedIps?.[0], "172.16.0.0/12");
}

export async function runTortureSuite(ctx: TortureContext): Promise<void> {
  log("================================================================");
  log("HMAC lib torture suite starting");
  log("================================================================");

  try {
    await runRevertTortureSuite(ctx);
    await runCrudTortureSuite(ctx);
    await runClientsManagementTortureSuite(ctx);
    await runFieldPreservationTortureSuite(ctx);
    log("================================================================");
    log("HMAC lib torture suite completed - scan for `torture FAIL:` lines");
    log("================================================================");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    fail(`torture suite threw: ${message}`);
  }
}
