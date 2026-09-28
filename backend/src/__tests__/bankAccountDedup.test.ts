// Copyright (c) 2026 RemitMortgage Protocol Contributors
// SPDX-License-Identifier: MIT

/**
 * Duplicate bank account detection across applicants (issue #747).
 *
 * Prisma is replaced with in-memory tables so the real hashing, matching and
 * flagging code runs end to end. Covers: no match, exact match (including
 * formatting differences), an applicant re-linking their own previously used
 * account (must not false-positive), reviewer context, and the guarantee that
 * raw account numbers are never stored, returned, or logged.
 */

import express from "express";
import request from "supertest";

let mockSecret = "test-bank-secret";

type Applicant = { id: string; stellarAddress: string; deletedAt: Date | null; createdAt: Date };
type Link = { id: string; applicantId: string; accountHash: string; accountLast4: string; linkedAt: Date };
type Loan = {
  id: string;
  applicantId: string;
  status: string;
  deletedAt: Date | null;
  manualReviewReason: string | null;
  principal: number;
  createdAt: Date;
};

const applicants: Applicant[] = [];
const links: Link[] = [];
const loans: Loan[] = [];
const auditEntries: any[] = [];
const loggedMessages: string[] = [];

function matchesId(value: any, actual: string) {
  if (value === undefined) return true;
  if (typeof value === "string") return value === actual;
  if (value.not !== undefined) return actual !== value.not;
  if (value.in) return value.in.includes(actual);
  return true;
}

function applicantOf(link: Link) {
  return applicants.find((a) => a.id === link.applicantId)!;
}

function linkMatches(link: Link, where: any = {}) {
  if (!matchesId(where.applicantId, link.applicantId)) return false;
  if (!matchesId(where.accountHash, link.accountHash)) return false;
  if (where.applicant) {
    const a = applicantOf(link);
    if (where.applicant.deletedAt === null && a.deletedAt !== null) return false;
    if (where.applicant.stellarAddress && a.stellarAddress !== where.applicant.stellarAddress) return false;
  }
  return true;
}

function withApplicant(link: Link) {
  const a = applicantOf(link);
  return {
    ...link,
    applicant: {
      ...a,
      loanApplications: loans
        .filter((l) => l.applicantId === a.id && l.deletedAt === null)
        .sort((x, y) => y.createdAt.getTime() - x.createdAt.getTime()),
    },
  };
}

jest.mock("../config.js", () => ({
  DEFAULT_BANK_ACCOUNT_HASH_SECRET: "default_bank_account_hash_secret",
  loadConfig: () => ({ adminApiKey: "test-admin-key", bankAccountHashSecret: mockSecret }),
}));
jest.mock("../utils/logger.js", () => {
  const record = (...args: any[]) => {
    loggedMessages.push(JSON.stringify(args));
  };
  return { __esModule: true, default: { info: record, warn: record, error: record, debug: record } };
});
jest.mock("../services/audit.js", () => ({
  logAudit: async (entry: any) => {
    auditEntries.push(entry);
  },
}));
jest.mock("../services/db.js", () => ({
  prisma: {
    applicant: {
      findFirst: jest.fn(async ({ where }: any) =>
        applicants.find(
          (a) => a.stellarAddress === where.stellarAddress && (where.deletedAt !== null || a.deletedAt === null)
        ) ?? null
      ),
    },
    linkedBankAccount: {
      upsert: jest.fn(async ({ where, create }: any) => {
        const key = where.applicantId_accountHash;
        const existing = links.find((l) => l.applicantId === key.applicantId && l.accountHash === key.accountHash);
        if (existing) return existing;
        const row = { id: `link-${links.length + 1}`, linkedAt: new Date(), ...create };
        links.push(row);
        return row;
      }),
      findMany: jest.fn(async ({ where }: any) => links.filter((l) => linkMatches(l, where)).map(withApplicant)),
      findFirst: jest.fn(async ({ where }: any) => {
        const found = links.find((l) => linkMatches(l, where));
        return found ? withApplicant(found) : null;
      }),
    },
    loanApplication: {
      findMany: jest.fn(async ({ where }: any) =>
        loans.filter(
          (l) =>
            matchesId(where.applicantId, l.applicantId) &&
            l.deletedAt === null &&
            !where.status.notIn.includes(l.status)
        )
      ),
      findFirst: jest.fn(async ({ where }: any) =>
        loans.find((l) => l.id === where.id && l.deletedAt === null) ?? null
      ),
      update: jest.fn(async ({ where, data }: any) => {
        const loan = loans.find((l) => l.id === where.id)!;
        Object.assign(loan, data);
        return loan;
      }),
    },
  },
}));

// Everything admin.ts and the ownership helper import that this suite does not exercise.
jest.mock("../services/loanStore.js", () => ({ getApplication: jest.fn(), bulkReviewApplications: jest.fn() }));
jest.mock("../services/inviteCode.js", () => ({ promoteWaitlistBatch: jest.fn() }));
jest.mock("../services/webhook.js", () => ({ sendWebhook: jest.fn() }));
jest.mock("../jobs/escrowReconciliation.js", () => ({ runEscrowReconciliation: jest.fn() }));
jest.mock("../services/applicantMerge.js", () => ({
  mergeApplicants: jest.fn(),
  MergeValidationError: class MergeValidationError extends Error {},
}));
jest.mock("../services/suspiciousActivity.js", () => ({ runSuspiciousActivityScan: jest.fn() }));
jest.mock("../services/autoRejectionRuleStore.js", () => ({
  listAutoRejectionRules: jest.fn(),
  createAutoRejectionRule: jest.fn(),
  updateAutoRejectionRule: jest.fn(),
}));
jest.mock("../middleware/auth.js", () => ({
  requireAdmin: (req: any, res: any, next: any) =>
    req.headers.authorization === "Bearer test-admin-key" ? next() : res.status(401).json({ error: "unauthorized" }),
}));

import { normalizeBankAccount, hashBankAccount, bankAccountLast4 } from "../utils/bankAccountHash.js";
import {
  linkBankAccount,
  flagApplicationIfSharedBankAccount,
  getBankAccountMatchesForApplication,
  BankAccountError,
  DUPLICATE_BANK_ACCOUNT_REVIEW_REASON,
} from "../services/bankAccountDedup.js";
import { bankAccountBorrowerRouter } from "../routes/bankAccount.js";
import { adminRouter } from "../routes/admin.js";
import { maskSensitiveData } from "../middleware/logMasker.js";

const ALICE = "GALICE";
const BOB = "GBOB";
const CAROL = "GCAROL";
const ACCOUNT = { bankCode: "021000021", accountNumber: "000123456789" };
const RAW_ACCOUNT_NUMBER = "000123456789";

function addApplicant(stellarAddress: string, extra: Partial<Applicant> = {}) {
  const applicant = { id: `ap-${applicants.length + 1}`, stellarAddress, deletedAt: null, createdAt: new Date(), ...extra };
  applicants.push(applicant);
  return applicant;
}

function addLoan(applicantId: string, status = "Pending", manualReviewReason: string | null = null) {
  const loan: Loan = {
    id: `loan-${loans.length + 1}`,
    applicantId,
    status,
    deletedAt: null,
    manualReviewReason,
    principal: 1000,
    createdAt: new Date(2026, 0, loans.length + 1),
  };
  loans.push(loan);
  return loan;
}

const link = (stellarAddress: string, account: { bankCode: string; accountNumber: string } = ACCOUNT) =>
  linkBankAccount({ stellarAddress, ...account });

beforeEach(() => {
  applicants.length = 0;
  links.length = 0;
  loans.length = 0;
  auditEntries.length = 0;
  loggedMessages.length = 0;
  mockSecret = "test-bank-secret";
});

describe("bank account hashing", () => {
  it("normalizes formatting and case, and requires both parts", () => {
    expect(normalizeBankAccount("021-000-021", "0001 2345 6789")).toEqual({
      bankCode: "021000021",
      accountNumber: "000123456789",
    });
    expect(normalizeBankAccount("gb29 nwbk", "6016 1331 9268 19")).toEqual({
      bankCode: "GB29NWBK",
      accountNumber: "60161331926819",
    });
    expect(normalizeBankAccount("", "123")).toBeNull();
    expect(normalizeBankAccount("021", " - ")).toBeNull();
    expect(normalizeBankAccount(undefined, "123")).toBeNull();
    expect(normalizeBankAccount({}, "123")).toBeNull();
  });

  it("hashes formatting variants to one value that never contains the raw number", () => {
    const a = hashBankAccount(normalizeBankAccount("021000021", "000123456789")!);
    const b = hashBankAccount(normalizeBankAccount("021-000-021", "0001 2345 6789")!);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(b).toBe(a);
    expect(a).not.toContain("123456789");
  });

  it("does not collide when digits shift between bank code and account number", () => {
    const a = hashBankAccount({ bankCode: "12", accountNumber: "345" });
    const b = hashBankAccount({ bankCode: "123", accountNumber: "45" });
    expect(a).not.toBe(b);
  });

  it("depends on the secret key", () => {
    const account = normalizeBankAccount("021", "999")!;
    const first = hashBankAccount(account);
    mockSecret = "another-secret";
    expect(hashBankAccount(account)).not.toBe(first);
  });

  it("refuses to hash with the development default secret in production", () => {
    const previous = process.env.NODE_ENV;
    mockSecret = "default_bank_account_hash_secret";
    try {
      process.env.NODE_ENV = "production";
      expect(() => hashBankAccount({ bankCode: "021", accountNumber: "999" })).toThrow(/BANK_ACCOUNT_HASH_SECRET/);
      process.env.NODE_ENV = "test";
      expect(() => hashBankAccount({ bankCode: "021", accountNumber: "999" })).not.toThrow();
    } finally {
      process.env.NODE_ENV = previous;
    }
  });

  it("keeps only the last four digits for display", () => {
    expect(bankAccountLast4({ bankCode: "021", accountNumber: "000123456789" })).toBe("6789");
  });
});

describe("linkBankAccount", () => {
  it("no match: links an unshared account without flagging anything", async () => {
    const alice = addApplicant(ALICE);
    const loan = addLoan(alice.id);
    addApplicant(BOB);

    const result = await link(ALICE);

    expect(result).toEqual({ accountLast4: "6789", duplicateDetected: false, flaggedApplicationIds: [] });
    expect(links).toHaveLength(1);
    expect(loan.manualReviewReason).toBeNull();
    expect(auditEntries).toHaveLength(0);
  });

  it("stores only the keyed hash and last four digits, never the raw account details", async () => {
    addApplicant(ALICE);
    await link(ALICE);

    expect(Object.keys(links[0]).sort()).toEqual(["accountHash", "accountLast4", "applicantId", "id", "linkedAt"]);
    expect(JSON.stringify(links)).not.toContain(RAW_ACCOUNT_NUMBER);
    expect(JSON.stringify(links)).not.toContain(ACCOUNT.bankCode);
  });

  it("exact match: flags open applications of both applicants", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const alicePending = addLoan(alice.id, "Pending");
    const aliceApproved = addLoan(alice.id, "Approved");
    const aliceCompleted = addLoan(alice.id, "Completed");
    const aliceRejected = addLoan(alice.id, "Rejected");
    const bobPending = addLoan(bob.id, "Pending");

    await link(ALICE);
    expect(alicePending.manualReviewReason).toBeNull();

    const result = await link(BOB);

    expect(result.duplicateDetected).toBe(true);
    expect(alicePending.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
    expect(aliceApproved.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
    expect(bobPending.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
    // Finished applications have nothing left to review.
    expect(aliceCompleted.manualReviewReason).toBeNull();
    expect(aliceRejected.manualReviewReason).toBeNull();
    expect(result.flaggedApplicationIds.sort()).toEqual([alicePending.id, aliceApproved.id, bobPending.id].sort());
  });

  it("exact match survives formatting differences in how the account was typed", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    const bobLoan = addLoan(bob.id);

    await link(ALICE, { bankCode: "021000021", accountNumber: "000123456789" });
    await link(BOB, { bankCode: "021-000-021", accountNumber: "0001 2345 6789" });

    expect(aliceLoan.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
    expect(bobLoan.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
  });

  it("same applicant re-linking their own account does not false-positive", async () => {
    const alice = addApplicant(ALICE);
    const loan = addLoan(alice.id);

    await link(ALICE);
    const again = await link(ALICE);

    expect(again.duplicateDetected).toBe(false);
    expect(links).toHaveLength(1);
    expect(loan.manualReviewReason).toBeNull();
    expect(auditEntries).toHaveLength(0);
  });

  it("same applicant returning to a previously used account does not false-positive", async () => {
    const alice = addApplicant(ALICE);
    const loan = addLoan(alice.id);
    const other = { bankCode: "011401533", accountNumber: "555000111" };

    await link(ALICE);
    await link(ALICE, other);
    const back = await link(ALICE);

    expect(back.duplicateDetected).toBe(false);
    expect(links).toHaveLength(2);
    expect(loan.manualReviewReason).toBeNull();
  });

  it("same account number at a different bank is not a match", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    const bobLoan = addLoan(bob.id);

    await link(ALICE, { bankCode: "021000021", accountNumber: "777" });
    const result = await link(BOB, { bankCode: "011401533", accountNumber: "777" });

    expect(result.duplicateDetected).toBe(false);
    expect(aliceLoan.manualReviewReason).toBeNull();
    expect(bobLoan.manualReviewReason).toBeNull();
  });

  it("flags every applicant in a ring sharing one account", async () => {
    const loansById = [ALICE, BOB, CAROL].map((address) => addLoan(addApplicant(address).id));

    await link(ALICE);
    await link(BOB);
    await link(CAROL);

    for (const loan of loansById) expect(loan.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
  });

  it("ignores links that belong to deleted applicants", async () => {
    const alice = addApplicant(ALICE, { deletedAt: new Date() });
    addLoan(alice.id);
    const bob = addApplicant(BOB);
    const bobLoan = addLoan(bob.id);
    links.push({
      id: "old",
      applicantId: alice.id,
      accountHash: hashBankAccount(normalizeBankAccount(ACCOUNT.bankCode, ACCOUNT.accountNumber)!),
      accountLast4: "6789",
      linkedAt: new Date(),
    });

    const result = await link(BOB);

    expect(result.duplicateDetected).toBe(false);
    expect(bobLoan.manualReviewReason).toBeNull();
  });

  it("keeps an existing review reason and adds the new one once", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id, "Pending", "DUPLICATE_TAX_ID");
    addLoan(bob.id);

    await link(ALICE);
    await link(BOB);
    expect(aliceLoan.manualReviewReason).toBe("DUPLICATE_TAX_ID,DUPLICATE_BANK_ACCOUNT");

    // Linking again (either side) does not stack the reason.
    await link(BOB);
    await link(ALICE);
    expect(aliceLoan.manualReviewReason).toBe("DUPLICATE_TAX_ID,DUPLICATE_BANK_ACCOUNT");
  });

  it("audits a detection with applicant ids only, no account number or hash", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    addLoan(alice.id);
    await link(ALICE);
    await linkBankAccount({ stellarAddress: BOB, ...ACCOUNT, ipAddress: "10.0.0.5" });

    expect(auditEntries).toEqual([
      expect.objectContaining({
        action: "DUPLICATE_BANK_ACCOUNT_DETECTED",
        actorAddress: BOB,
        ipAddress: "10.0.0.5",
        metadata: expect.objectContaining({
          applicantId: bob.id,
          matchedApplicantIds: [alice.id],
          accountLast4: "6789",
        }),
      }),
    ]);
    const everything = JSON.stringify({ auditEntries, loggedMessages });
    expect(everything).not.toContain(RAW_ACCOUNT_NUMBER);
    expect(everything).not.toContain(links[0].accountHash);
  });

  it("rejects missing details and unknown applicants", async () => {
    addApplicant(ALICE);
    await expect(link(ALICE, { bankCode: "021", accountNumber: "" })).rejects.toMatchObject({
      code: "invalid_bank_account",
      httpStatus: 400,
    });
    await expect(link("GNOBODY")).rejects.toBeInstanceOf(BankAccountError);
    await expect(link("GNOBODY")).rejects.toMatchObject({ code: "not_found", httpStatus: 404 });
    expect(links).toHaveLength(0);
  });
});

describe("flagApplicationIfSharedBankAccount", () => {
  it("holds a new application when its applicant already shares an account", async () => {
    const alice = addApplicant(ALICE);
    addApplicant(BOB);
    await link(ALICE);
    await link(BOB);
    const fresh = addLoan(alice.id);

    const reason = await flagApplicationIfSharedBankAccount(fresh.id, ALICE);

    expect(reason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
    expect(fresh.manualReviewReason).toBe(DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
  });

  it("adds to an existing reason rather than replacing it", async () => {
    const alice = addApplicant(ALICE);
    addApplicant(BOB);
    await link(ALICE);
    await link(BOB);
    const fresh = addLoan(alice.id, "Pending", "DUPLICATE_TAX_ID");

    expect(await flagApplicationIfSharedBankAccount(fresh.id, ALICE)).toBe("DUPLICATE_TAX_ID,DUPLICATE_BANK_ACCOUNT");
  });

  it("leaves applications alone when nothing is shared or nothing is linked", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    const bobLoan = addLoan(bob.id);
    await link(ALICE);

    expect(await flagApplicationIfSharedBankAccount(aliceLoan.id, ALICE)).toBeNull();
    expect(await flagApplicationIfSharedBankAccount(bobLoan.id, BOB)).toBeNull();
    expect(aliceLoan.manualReviewReason).toBeNull();
    expect(bobLoan.manualReviewReason).toBeNull();
  });

  it("does not flag an applicant re-using only their own account", async () => {
    const alice = addApplicant(ALICE);
    await link(ALICE);
    await link(ALICE);
    const loan = addLoan(alice.id);

    expect(await flagApplicationIfSharedBankAccount(loan.id, ALICE)).toBeNull();
  });
});

describe("getBankAccountMatchesForApplication", () => {
  it("shows matched applicants and their applications with masked accounts only", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    const bobLoan = addLoan(bob.id, "Approved");
    await link(ALICE);
    await link(BOB);

    const result = await getBankAccountMatchesForApplication(aliceLoan.id);

    expect(result).toMatchObject({
      applicationId: aliceLoan.id,
      manualReviewReason: DUPLICATE_BANK_ACCOUNT_REVIEW_REASON,
      matchedApplicantCount: 1,
    });
    expect(result!.matches).toEqual([
      expect.objectContaining({
        applicantId: bob.id,
        stellarAddress: BOB,
        sharedAccountLast4: ["6789"],
        applications: [expect.objectContaining({ id: bobLoan.id, status: "Approved" })],
      }),
    ]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(RAW_ACCOUNT_NUMBER);
    for (const l of links) expect(serialized).not.toContain(l.accountHash);
  });

  it("reports one entry per matched applicant even when several accounts are shared", async () => {
    const alice = addApplicant(ALICE);
    addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    const second = { bankCode: "011401533", accountNumber: "555000111" };
    await link(ALICE);
    await link(ALICE, second);
    await link(BOB);
    await link(BOB, second);

    const result = await getBankAccountMatchesForApplication(aliceLoan.id);

    expect(result!.matchedApplicantCount).toBe(1);
    expect(result!.matches[0].sharedAccountLast4.sort()).toEqual(["0111", "6789"]);
  });

  it("returns no matches for an unshared account or an applicant with no account, and null for an unknown loan", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    const bobLoan = addLoan(bob.id);
    await link(ALICE);

    expect(await getBankAccountMatchesForApplication(aliceLoan.id)).toMatchObject({ matchedApplicantCount: 0, matches: [] });
    expect(await getBankAccountMatchesForApplication(bobLoan.id)).toMatchObject({ matchedApplicantCount: 0, matches: [] });
    expect(await getBankAccountMatchesForApplication("missing")).toBeNull();
  });
});

describe("HTTP routes", () => {
  const app = express();
  app.use(express.json());
  // Stand-in for authMiddleware: identify the caller by header.
  app.use((req: any, _res, next) => {
    const wallet = req.headers["x-test-wallet"];
    if (wallet) req.user = { walletAddress: String(wallet), network: "testnet" };
    next();
  });
  app.use("/api/borrower", bankAccountBorrowerRouter);
  app.use("/api/admin", adminRouter);

  const linkAs = (wallet: string | undefined, path: string, body: object) => {
    const req = request(app).post(`/api/borrower/${path}/bank-account`);
    return (wallet ? req.set("x-test-wallet", wallet) : req).send(body);
  };

  it("requires authentication and ownership of the address", async () => {
    addApplicant(ALICE);
    expect((await linkAs(undefined, ALICE, ACCOUNT)).status).toBe(401);
    expect((await linkAs(BOB, ALICE, ACCOUNT)).status).toBe(403);
    expect(links).toHaveLength(0);
  });

  it("links an account and returns only the masked last four digits", async () => {
    addApplicant(ALICE);
    const res = await linkAs(ALICE, ALICE, ACCOUNT);

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ linked: true, accountLast4: "6789" });
  });

  it("responds identically whether or not the account is already linked elsewhere", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    addLoan(alice.id);
    addLoan(bob.id);

    const first = await linkAs(ALICE, ALICE, ACCOUNT);
    const duplicate = await linkAs(BOB, BOB, ACCOUNT);

    expect(duplicate.status).toBe(first.status);
    expect(duplicate.body).toEqual(first.body);
    expect(loans.every((l) => l.manualReviewReason === DUPLICATE_BANK_ACCOUNT_REVIEW_REASON)).toBe(true);
  });

  it("rejects invalid bodies and unknown applicants", async () => {
    addApplicant(ALICE);
    const bad = await linkAs(ALICE, ALICE, { bankCode: "021" });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe("invalid_bank_account");
    expect((await linkAs(CAROL, CAROL, ACCOUNT)).status).toBe(404);
  });

  it("gives admins reviewer context and requires admin auth for it", async () => {
    const alice = addApplicant(ALICE);
    const bob = addApplicant(BOB);
    const aliceLoan = addLoan(alice.id);
    addLoan(bob.id);
    await link(ALICE);
    await link(BOB);

    const url = `/api/admin/loans/${aliceLoan.id}/bank-account-matches`;
    expect((await request(app).get(url)).status).toBe(401);

    const res = await request(app).get(url).set("Authorization", "Bearer test-admin-key");
    expect(res.status).toBe(200);
    expect(res.body.matchedApplicantCount).toBe(1);
    expect(res.body.matches[0].sharedAccountLast4).toEqual(["6789"]);
    expect(JSON.stringify(res.body)).not.toContain(RAW_ACCOUNT_NUMBER);

    const missing = await request(app)
      .get("/api/admin/loans/nope/bank-account-matches")
      .set("Authorization", "Bearer test-admin-key");
    expect(missing.status).toBe(404);
  });
});

describe("request log masking", () => {
  it("masks bank account fields in logged request bodies", () => {
    const masked = JSON.stringify(
      maskSensitiveData({ bankCode: "021000021", accountNumber: RAW_ACCOUNT_NUMBER, bankAccountNumber: "1", routingNumber: "2" })
    );
    expect(masked).not.toContain(RAW_ACCOUNT_NUMBER);
    expect(masked).not.toContain('"1"');
    expect(masked).not.toContain('"2"');
  });
});
