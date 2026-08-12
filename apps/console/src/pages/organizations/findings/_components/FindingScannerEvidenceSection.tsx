// Copyright (c) 2026 Probo Inc <hello@probo.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import { Card } from "@probo/ui";
import { useTranslation } from "react-i18next";
import { graphql, useFragment } from "react-relay";

import type { FindingScannerEvidenceSection_finding$key } from "#/__generated__/core/FindingScannerEvidenceSection_finding.graphql";

const findingFragment = graphql`
  fragment FindingScannerEvidenceSection_finding on Finding {
    malaysiaPDPAScannerFinding {
      source
      ruleVersion
      evidence
    }
  }
`;

interface FindingScannerEvidenceSectionProps {
  findingKey: FindingScannerEvidenceSection_finding$key;
}

export function FindingScannerEvidenceSection({
  findingKey,
}: FindingScannerEvidenceSectionProps) {
  const { t } = useTranslation();
  const finding = useFragment(findingFragment, findingKey);
  const scannerFinding = finding.malaysiaPDPAScannerFinding;

  if (!scannerFinding) {
    return null;
  }

  return (
    <Card padded className="space-y-5">
      <div className="space-y-1">
        <h2 className="text-base font-medium">
          {t("findingDetails.scannerEvidence.title")}
        </h2>
        <p className="text-sm text-txt-tertiary">
          {t("findingDetails.scannerEvidence.description")}
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <MetadataBlock
          label={t("findingDetails.scannerEvidence.source")}
          value={scannerFinding.source}
        />
        <MetadataBlock
          label={t("findingDetails.scannerEvidence.ruleVersion")}
          value={scannerFinding.ruleVersion}
        />
      </div>

      <div className="space-y-2">
        <h3 className="text-xs font-medium text-txt-tertiary">
          {t("findingDetails.scannerEvidence.evidence")}
        </h3>
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-subtle p-4 font-mono text-xs text-txt-secondary">
          {formatEvidence(scannerFinding.evidence)}
        </pre>
      </div>
    </Card>
  );
}

interface MetadataBlockProps {
  label: string;
  value: string;
}

function MetadataBlock({ label, value }: MetadataBlockProps) {
  return (
    <div className="space-y-1 rounded-xl border border-border-low p-4">
      <p className="text-xs font-medium text-txt-tertiary">{label}</p>
      <p className="break-words text-sm text-txt-secondary">{value}</p>
    </div>
  );
}

function formatEvidence(evidence: string): string {
  try {
    return JSON.stringify(JSON.parse(evidence), null, 2);
  } catch {
    return evidence;
  }
}
