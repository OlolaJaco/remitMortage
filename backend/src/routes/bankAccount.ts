// Copyright (c) 2026 RemitMortgage Protocol Contributors
// SPDX-License-Identifier: MIT

/**
 * Borrower bank account linking (issue #747):
 *   POST /api/borrower/:address/bank-account — link an account for payout
 *
 * The response is identical whether or not the account is already linked to
 * another applicant. Revealing a match would tell someone probing for
 * duplicates which accounts are shared; reviewers see it via
 * GET /api/admin/loans/:id/bank-account-matches instead.
 */

import { Router, Response } from "express";
import type { AuthenticatedRequest } from "../middleware/auth.js";
import { requireBorrowerAddressOwnership } from "../security/requireResourceOwnership.js";
import { linkBankAccount, BankAccountError } from "../services/bankAccountDedup.js";
import logger from "../utils/logger.js";

export const bankAccountBorrowerRouter = Router();

bankAccountBorrowerRouter.post("/:address/bank-account", async (req: AuthenticatedRequest, res: Response) => {
  const address = String(req.params?.address ?? "");
  if (!requireBorrowerAddressOwnership(req, res, address)) return;
  const body = req.body ?? {};
  try {
    const { accountLast4 } = await linkBankAccount({
      stellarAddress: address,
      bankCode: body.bankCode,
      accountNumber: body.accountNumber,
      ipAddress: req.ip,
    });
    return res.status(201).json({ linked: true, accountLast4 });
  } catch (err) {
    if (err instanceof BankAccountError) {
      return res.status(err.httpStatus).json({ error: err.code, message: err.message });
    }
    // Deliberately no request body in the log: it holds the account number.
    logger.error("Bank account link failed", { err });
    return res.status(500).json({ error: "bank_account_link_failed" });
  }
});
