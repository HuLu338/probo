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

import type { IExecuteFunctions } from 'n8n-workflow';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { proboApiRequest } from '../nodes/Probo/GenericFunctions';
import { incidentFields } from '../nodes/Probo/actions/malaysiaPDPABreach/fields';
import { execute } from '../nodes/Probo/actions/malaysiaPDPA/get.operation';

vi.mock('../nodes/Probo/GenericFunctions', () => ({
	proboApiRequest: vi.fn(),
}));

describe('Malaysia PDPA n8n operations', () => {
	const proboApiRequestMock = vi.mocked(proboApiRequest);

	beforeEach(() => {
		proboApiRequestMock.mockReset();
	});

	it('selects DPO assessment rule provenance when getting a profile', async () => {
		proboApiRequestMock.mockResolvedValue({ data: {} });
		const context = {
			getNodeParameter: vi.fn().mockReturnValue('organization-id'),
		} as unknown as IExecuteFunctions;

		await execute.call(context, 0);

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
});
