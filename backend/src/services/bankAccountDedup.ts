// Copyright (c) 2026 RemitMortgage Protocol Contributors
// SPDX-License-Identifier: MIT

/**
 * Duplicate bank account detection across applicants (issue #747).
 *
 * A linked account is stored only as a keyed HMAC of its normalized bank code
 * and account number (plus the last four digits for masked display). When the
 * same hash is already linked to a different applicant, the live applications
 * of both are held for manual review rather than silently allowed or rejected.
 * Raw account details are never stored, logged, or returned, and the hash
 * itself is never returned by the reviewer endpoint.
 */

import { prisma } from "./db.js";
import { logAudit } from "./audit.js";
import { normalizeBankAccount, hashBankAccount, bankAccountLast4 } from "../utils/bankAccountHash.js";
import logger from "../utils/logger.js";

export const DUPLICATE_BANK_ACCOUNT_REVIEW_REASON = "DUPLICATE_BANK_ACCOUNT";

/** Applications in these statuses are finished, so there is nothing left to review. */
const CLOSED_STATUSES = ["Rejected", "Completed"];

export class BankAccountError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 400
  ) {
    super(message);
  }
}

/**
 * manualReviewReason is a single string, so several reasons are kept
 * comma-separated (e.g. "DUPLICATE_TAX_ID,DUPLICATE_BANK_ACCOUNT").
 */
function withReason(existing: string | null | undefined, reason: string): string {
  const reasons = existing ? existing.split(",") : [];
  return reasons.includes(reason) ? reasons.join(",") : [...reasons, reason].join(",");
}

/** Adds the duplicate-bank-account hold to each open application; returns the ids that changed. */
async function flagOpenApplications(applicantIds: string[]): Promise<string[]> {
  const applications = await prisma.loanApplication.findMany({
    where: { applicantId: { in: applicantIds }, deletedAt: null, status: { notIn: CLOSED_STATUSES as any } },
    select: { id: true, manualReviewReason: true },
  });

  const flagged: string[] = [];
  for (const application of applications) {
    const manualReviewReason = withReason(application.manualReviewReason, DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
    if (manualReviewReason === application.manualReviewReason) continue;
    await prisma.loanApplication.update({ where: { id: application.id }, data: { manualReviewReason } });
    flagged.push(application.id);
  }
  return flagged;
}

export interface LinkBankAccountInput {
  stellarAddress: string;
  bankCode: unknown;
  accountNumber: unknown;
  ipAddress?: string;
}

export interface LinkBankAccountResult {
  accountLast4: string;
  /**
   * Whether another applicant already had this account. For internal use and
   * tests only: the borrower-facing response must not reveal it.
   */
  duplicateDetected: boolean;
  flaggedApplicationIds: string[];
}

/**
 * Links a bank account to an applicant and checks it against every other
 * applicant. Re-linking an account the applicant already used is a no-op and
 * never matches against themselves.
 */
export async function linkBankAccount(input: LinkBankAccountInput): Promise<LinkBankAccountResult> {
  const account = normalizeBankAccount(input.bankCode, input.accountNumber);
  if (!account) {
    throw new BankAccountError("invalid_bank_account", "bankCode and accountNumber are required");
  }
  const accountHash = hashBankAccount(account);
  const accountLast4 = bankAccountLast4(account);

  const applicant = await prisma.applicant.findFirst({
    where: { stellarAddress: input.stellarAddress, deletedAt: null },
    select: { id: true },
  });
  if (!applicant) {
    throw new BankAccountError("not_found", "Applicant not found", 404);
  }

  // Write first, then look for other owners. If two applicants link the same
  // account at the same moment, each one's check runs after its own insert, so
  // at least one of them sees the other and both get flagged.
  await prisma.linkedBankAccount.upsert({
    where: { applicantId_accountHash: { applicantId: applicant.id, accountHash } },
    create: { applicantId: applicant.id, accountHash, accountLast4 },
    update: {},
  });

  const others = await prisma.linkedBankAccount.findMany({
    where: { accountHash, applicantId: { not: applicant.id }, applicant: { deletedAt: null } },
    select: { applicantId: true },
  });
  const otherApplicantIds = [...new Set<string>(others.map((o: { applicantId: string }) => o.applicantId))];
  if (otherApplicantIds.length === 0) {
    return { accountLast4, duplicateDetected: false, flaggedApplicationIds: [] };
  }

  const flaggedApplicationIds = await flagOpenApplications([applicant.id, ...otherApplicantIds]);

  // Applicant ids only: never the account number or its hash.
  await logAudit({
    action: "DUPLICATE_BANK_ACCOUNT_DETECTED",
    actorAddress: input.stellarAddress,
    ipAddress: input.ipAddress,
    metadata: {
      applicantId: applicant.id,
      matchedApplicantIds: otherApplicantIds,
      flaggedApplicationIds,
      accountLast4,
    },
  });
  logger.warn(
    `Bank account linked by applicant ${applicant.id} matches ${otherApplicantIds.length} other applicant(s); ` +
      `${flaggedApplicationIds.length} application(s) held for manual review`
  );

  return { accountLast4, duplicateDetected: true, flaggedApplicationIds };
}

/**
 * Holds a newly created application when its applicant already shares a linked
 * account with someone else (the account was linked before the application
 * existed, so the link-time flagging could not cover it). Returns the
 * application's updated manualReviewReason, or null when nothing was flagged.
 */
export async function flagApplicationIfSharedBankAccount(
  applicationId: string,
  stellarAddress: string
): Promise<string | null> {
  const links = await prisma.linkedBankAccount.findMany({
    where: { applicant: { stellarAddress, deletedAt: null } },
    select: { applicantId: true, accountHash: true },
  });
  if (links.length === 0) return null;

  const shared = await prisma.linkedBankAccount.findFirst({
    where: {
      accountHash: { in: links.map((l: { accountHash: string }) => l.accountHash) },
      applicantId: { not: links[0].applicantId },
      applicant: { deletedAt: null },
    },
    select: { id: true },
  });
  if (!shared) return null;

  const application = await prisma.loanApplication.findFirst({
    where: { id: applicationId, deletedAt: null },
    select: { manualReviewReason: true },
  });
  if (!application) return null;

  const manualReviewReason = withReason(application.manualReviewReason, DUPLICATE_BANK_ACCOUNT_REVIEW_REASON);
  await prisma.loanApplication.update({ where: { id: applicationId }, data: { manualReviewReason } });
  return manualReviewReason;
}

export interface BankAccountMatch {
  applicantId: string;
  stellarAddress: string;
  applicantCreatedAt: Date;
  /** Last four digits of each account shared with the reviewed applicant. */
  sharedAccountLast4: string[];
  applications: { id: string; status: string; principal: number; createdAt: Date }[];
}

/**
 * Reviewer context for a loan application: which other applicants share a
 * bank account with its applicant. Accounts appear only as last four digits;
 * the hash and the account number are never returned. Returns null when the
 * application does not exist.
 */
export async function getBankAccountMatchesForApplication(applicationId: string) {
  const application = await prisma.loanApplication.findFirst({
    where: { id: applicationId, deletedAt: null },
    select: { id: true, applicantId: true, manualReviewReason: true },
  });
  if (!application) return null;

  const own = await prisma.linkedBankAccount.findMany({
    where: { applicantId: application.applicantId },
    select: { accountHash: true },
  });

  const shared = own.length
    ? await prisma.linkedBankAccount.findMany({
        where: {
          accountHash: { in: own.map((o: { accountHash: string }) => o.accountHash) },
          applicantId: { not: application.applicantId },
          applicant: { deletedAt: null },
        },
        select: {
          accountLast4: true,
          applicant: {
            select: {
              id: true,
              stellarAddress: true,
              createdAt: true,
              loanApplications: {
                where: { deletedAt: null },
                select: { id: true, status: true, principal: true, createdAt: true },
                orderBy: { createdAt: "desc" },
              },
            },
          },
        },
      })
    : [];

  const byApplicant = new Map<string, BankAccountMatch>();
  for (const row of shared as any[]) {
    const match: BankAccountMatch = byApplicant.get(row.applicant.id) ?? {
      applicantId: row.applicant.id,
      stellarAddress: row.applicant.stellarAddress,
      applicantCreatedAt: row.applicant.createdAt,
      sharedAccountLast4: [],
      applications: row.applicant.loanApplications,
    };
    if (!match.sharedAccountLast4.includes(row.accountLast4)) match.sharedAccountLast4.push(row.accountLast4);
    byApplicant.set(row.applicant.id, match);
  }

  const matches = [...byApplicant.values()];
  return {
    applicationId: application.id,
    manualReviewReason: application.manualReviewReason,
    matchedApplicantCount: matches.length,
    matches,
  };
}
