// Copyright (c) 2026 RemitMortgage Protocol Contributors
// SPDX-License-Identifier: MIT

import { createHmac } from "crypto";
import { loadConfig, DEFAULT_BANK_ACCOUNT_HASH_SECRET } from "../config.js";

export interface NormalizedBankAccount {
  bankCode: string;
  accountNumber: string;
}

function normalizePart(raw: unknown): string | null {
  if (typeof raw !== "string" && typeof raw !== "number") return null;
  // "1234-5678", "1234 5678" and "12345678" compare equal; IBANs are case-insensitive.
  const normalized = String(raw).replace(/[^0-9a-z]/gi, "").toUpperCase();
  return normalized.length > 0 ? normalized : null;
}

/** Strips formatting from both parts. Null when either is missing or empty. */
export function normalizeBankAccount(bankCode: unknown, accountNumber: unknown): NormalizedBankAccount | null {
  const code = normalizePart(bankCode);
  const number = normalizePart(accountNumber);
  return code && number ? { bankCode: code, accountNumber: number } : null;
}

/**
 * Keyed HMAC of a normalized bank account, used to find the same account under
 * other applicants without storing the account number. Account numbers are
 * low-entropy, so the key is what protects them: production refuses to hash
 * with the development default.
 */
export function hashBankAccount(account: NormalizedBankAccount): string {
  const { bankAccountHashSecret } = loadConfig();
  if (process.env.NODE_ENV === "production" && bankAccountHashSecret === DEFAULT_BANK_ACCOUNT_HASH_SECRET) {
    throw new Error("BANK_ACCOUNT_HASH_SECRET must be set in production");
  }
  // Length-prefix the bank code so ("12","345") and ("123","45") never collide.
  return createHmac("sha256", bankAccountHashSecret)
    .update(`${account.bankCode.length}:${account.bankCode}:${account.accountNumber}`)
    .digest("hex");
}

export function bankAccountLast4(account: NormalizedBankAccount): string {
  return account.accountNumber.slice(-4);
}
