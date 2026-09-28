-- Issue #747: duplicate bank account detection across applicants.
-- The raw account number is never stored. accountHash is a keyed HMAC of the
-- normalized bank code + account number, so the same account can be found
-- under other applicants by index. accountLast4 supports masked display.

CREATE TABLE "LinkedBankAccount" (
  "id" TEXT NOT NULL,
  "applicantId" TEXT NOT NULL,
  "accountHash" TEXT NOT NULL,
  "accountLast4" TEXT NOT NULL,
  "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "LinkedBankAccount_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "LinkedBankAccount_applicantId_accountHash_key"
  ON "LinkedBankAccount"("applicantId", "accountHash");
CREATE INDEX "LinkedBankAccount_accountHash_idx" ON "LinkedBankAccount"("accountHash");

ALTER TABLE "LinkedBankAccount"
  ADD CONSTRAINT "LinkedBankAccount_applicantId_fkey"
  FOREIGN KEY ("applicantId") REFERENCES "Applicant"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
