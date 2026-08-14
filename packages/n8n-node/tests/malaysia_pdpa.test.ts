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

import type { IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
	proboApiRequest,
	proboApiRequestAllItems,
} from '../nodes/Probo/GenericFunctions';
import { incidentFields } from '../nodes/Probo/actions/malaysiaPDPABreach/fields';
import { execute as getMalaysiaPDPAProfile } from '../nodes/Probo/actions/malaysiaPDPA/get.operation';
import { execute as getProcessingActivity } from '../nodes/Probo/actions/processingActivity/get.operation';
import { execute as getAllProcessingActivities } from '../nodes/Probo/actions/processingActivity/getAll.operation';
import { execute as updateProcessingActivity } from '../nodes/Probo/actions/processingActivity/update.operation';
import { execute as createTIA } from '../nodes/Probo/actions/tia/create.operation';
import { execute as getTIA } from '../nodes/Probo/actions/tia/get.operation';
import { execute as getAllTIAs } from '../nodes/Probo/actions/tia/getAll.operation';
import { execute as updateTIA } from '../nodes/Probo/actions/tia/update.operation';

vi.mock('../nodes/Probo/GenericFunctions', () => ({
	proboApiRequest: vi.fn(),
	proboApiRequestAllItems: vi.fn(),
}));

type Operation = (this: IExecuteFunctions, itemIndex: number) => Promise<INodeExecutionData>;

const malaysiaPDPADPIAFields = [
	'malaysiaPDPADPIATotalDataSubjects',
	'malaysiaPDPADPIASensitiveDataSubjects',
	'malaysiaPDPADPIALegalOrSignificantEffects',
	'malaysiaPDPADPIASystematicMonitoring',
	'malaysiaPDPADPIAInnovativeTechnology',
	'malaysiaPDPADPIADenialOrRestrictionOfRights',
	'malaysiaPDPADPIALocationOrBehaviourTracking',
	'malaysiaPDPADPIAChildrenOrVulnerableDataSubjects',
	'malaysiaPDPADPIAHighRiskAutomatedDecisionMaking',
	'malaysiaPDPADPIAOtherHighRiskFactors',
	'malaysiaPDPADPIARecommendation',
	'malaysiaPDPADPIAReasons',
	'malaysiaPDPADPIAAssessedByProfileId',
	'malaysiaPDPADPIAAssessedAt',
	'malaysiaPDPADPIARuleVersion',
	'malaysiaPDPADPIARuleSource',
];

const malaysiaTransferFields = [
	'malaysiaTransferBasis',
	'malaysiaDestinationCountry',
	'malaysiaRecipientThirdPartyId',
	'malaysiaReceiverRegistrationNumber',
	'malaysiaReceiverContact',
	'malaysiaTransferPurpose',
	'malaysiaPersonalDataCategories',
	'malaysiaSafeguards',
	'malaysiaApprovalStatus',
	'malaysiaApprovedByProfileId',
	'malaysiaApprovalNotes',
	'malaysiaReviewedAt',
	'malaysiaNextReviewAt',
	'malaysiaReviewEvidence',
	'malaysiaRuleVersion',
	'malaysiaRuleSource',
];

const processingActivityOperations: Array<{
	name: string;
	execute: Operation;
	parameters: Record<string, unknown>;
	paginated: boolean;
}> = [
	{
		name: 'get',
		execute: getProcessingActivity,
		parameters: { processingActivityId: 'processing-activity-id' },
		paginated: false,
	},
	{
		name: 'get all',
		execute: getAllProcessingActivities,
		parameters: { organizationId: 'organization-id', returnAll: false, limit: 50 },
		paginated: true,
	},
	{
		name: 'update',
		execute: updateProcessingActivity,
		parameters: { id: 'processing-activity-id', runMalaysiaPDPADPIAScreening: false },
		paginated: false,
	},
];

const tiaOperations: Array<{
	name: string;
	execute: Operation;
	parameters: Record<string, unknown>;
	paginated: boolean;
}> = [
	{
		name: 'create',
		execute: createTIA,
		parameters: { processingActivityId: 'processing-activity-id', includeMalaysiaPDPA: false },
		paginated: false,
	},
	{
		name: 'get',
		execute: getTIA,
		parameters: { transferImpactAssessmentId: 'tia-id' },
		paginated: false,
	},
	{
		name: 'get all',
		execute: getAllTIAs,
		parameters: { organizationId: 'organization-id', returnAll: false, limit: 50 },
		paginated: true,
	},
	{
		name: 'update',
		execute: updateTIA,
		parameters: { id: 'tia-id', includeMalaysiaPDPA: false },
		paginated: false,
	},
];

function createContext(parameters: Record<string, unknown>): IExecuteFunctions {
	return {
		getNodeParameter: vi.fn(
			(name: string, _itemIndex: number, fallback?: unknown) => parameters[name] ?? fallback ?? '',
		),
	} as unknown as IExecuteFunctions;
}

function expectQueryToContain(query: string, fields: string[]): void {
	for (const field of fields) {
		expect(query).toContain(field);
	}
}

describe('Malaysia PDPA n8n operations', () => {
	const proboApiRequestMock = vi.mocked(proboApiRequest);
	const proboApiRequestAllItemsMock = vi.mocked(proboApiRequestAllItems);

	beforeEach(() => {
		proboApiRequestMock.mockReset();
		proboApiRequestMock.mockResolvedValue({ data: {} });
		proboApiRequestAllItemsMock.mockReset();
		proboApiRequestAllItemsMock.mockResolvedValue([]);
	});

	it('selects DPO assessment rule provenance when getting a profile', async () => {
		const context = {
			getNodeParameter: vi.fn().mockReturnValue('organization-id'),
		} as unknown as IExecuteFunctions;

		await getMalaysiaPDPAProfile.call(context, 0);

		expect(proboApiRequestMock).toHaveBeenCalledOnce();
		const [query, variables] = proboApiRequestMock.mock.calls[0];
		expect(query).toContain('ruleVersion');
		expect(query).toContain('ruleSource');
		expect(variables).toEqual({ organizationId: 'organization-id' });
	});

	it('selects the phased-information overdue status for breach operations', () => {
		expect(incidentFields).toContain('phasedInformationDueAt');
		expect(incidentFields).toContain('phasedInformationOverdue');
	});

	it.each(processingActivityOperations)(
		'selects all Malaysia DPIA fields for processing activity $name',
		async ({ execute, parameters, paginated }) => {
			await execute.call(createContext(parameters), 0);

			const query = paginated
				? (proboApiRequestAllItemsMock.mock.calls[0][0] as string)
				: (proboApiRequestMock.mock.calls[0][0] as string);
			expectQueryToContain(query, malaysiaPDPADPIAFields);
		},
	);

	it.each(tiaOperations)(
		'selects all Malaysia transfer fields for TIA $name',
		async ({ execute, parameters, paginated }) => {
			await execute.call(createContext(parameters), 0);

			const query = paginated
				? (proboApiRequestAllItemsMock.mock.calls[0][0] as string)
				: (proboApiRequestMock.mock.calls[0][0] as string);
			expectQueryToContain(query, malaysiaTransferFields);
		},
	);
});
