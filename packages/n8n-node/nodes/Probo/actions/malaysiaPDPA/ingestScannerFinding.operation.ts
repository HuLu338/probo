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

import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeProperties,
} from 'n8n-workflow';
import { proboApiRequest } from '../../GenericFunctions';

const show = { resource: ['malaysiaPDPA'], operation: ['ingestScannerFinding'] };

export const description: INodeProperties[] = [
	{
		displayName: 'Organization ID',
		name: 'organizationId',
		type: 'string',
		displayOptions: { show },
		default: '',
		description: 'The ID of the organization',
		required: true,
	},
	{
		displayName: 'External ID',
		name: 'externalId',
		type: 'string',
		displayOptions: { show },
		default: '',
		description: 'Stable scanner-side finding identifier',
		required: true,
	},
	{
		displayName: 'Source',
		name: 'source',
		type: 'string',
		displayOptions: { show },
		default: '',
		description: 'Stable scanner integration name',
		required: true,
	},
	{
		displayName: 'Check Key',
		name: 'checkKey',
		type: 'options',
		displayOptions: { show },
		options: [
			{ name: 'Backup Evidence', value: 'BACKUP_EVIDENCE' },
			{ name: 'Configuration Weaknesses', value: 'CONFIGURATION_WEAKNESSES' },
			{ name: 'Exposed Services', value: 'EXPOSED_SERVICES' },
			{ name: 'MFA', value: 'MFA' },
			{ name: 'Privileged Accounts', value: 'PRIVILEGED_ACCOUNTS' },
			{ name: 'TLS', value: 'TLS' },
			{ name: 'Token Lifetime', value: 'TOKEN_LIFETIME' },
		],
		default: 'MFA',
		required: true,
	},
	{
		displayName: 'Severity',
		name: 'severity',
		type: 'options',
		displayOptions: { show },
		options: [
			{ name: 'Low', value: 'LOW' },
			{ name: 'Medium', value: 'MEDIUM' },
			{ name: 'High', value: 'HIGH' },
			{ name: 'Critical', value: 'CRITICAL' },
		],
		default: 'MEDIUM',
		required: true,
	},
	{
		displayName: 'Summary',
		name: 'summary',
		type: 'string',
		typeOptions: { rows: 3 },
		displayOptions: { show },
		default: '',
		required: true,
	},
	{
		displayName: 'Evidence',
		name: 'evidence',
		type: 'json',
		displayOptions: { show },
		default: '{ "observed": true }',
		description: 'Non-empty JSON object containing the scanner evidence',
		required: true,
	},
	{
		displayName: 'Observed At',
		name: 'observedAt',
		type: 'dateTime',
		displayOptions: { show },
		default: '',
		required: true,
	},
	{
		displayName: 'Rule Version',
		name: 'ruleVersion',
		type: 'string',
		displayOptions: { show },
		default: '',
		required: true,
	},
	{
		displayName: 'Rule Source',
		name: 'ruleSource',
		type: 'string',
		displayOptions: { show },
		default: '',
		required: true,
	},
];

export async function execute(
	this: IExecuteFunctions,
	itemIndex: number,
): Promise<INodeExecutionData> {
	const evidence = this.getNodeParameter('evidence', itemIndex) as string | IDataObject;
	const input: IDataObject = {
		organizationId: this.getNodeParameter('organizationId', itemIndex) as string,
		externalId: this.getNodeParameter('externalId', itemIndex) as string,
		source: this.getNodeParameter('source', itemIndex) as string,
		checkKey: this.getNodeParameter('checkKey', itemIndex) as string,
		severity: this.getNodeParameter('severity', itemIndex) as string,
		summary: this.getNodeParameter('summary', itemIndex) as string,
		evidence: typeof evidence === 'string' ? evidence : JSON.stringify(evidence),
		observedAt: this.getNodeParameter('observedAt', itemIndex) as string,
		ruleVersion: this.getNodeParameter('ruleVersion', itemIndex) as string,
		ruleSource: this.getNodeParameter('ruleSource', itemIndex) as string,
	};

	const mutation = `
		mutation IngestMalaysiaPDPAScannerFinding($input: IngestMalaysiaPDPAScannerFindingInput!) {
			ingestMalaysiaPDPAScannerFinding(input: $input) {
				created
				scannerFinding {
					id
					organizationId
					externalId
					source
					checkKey
					severity
					summary
					evidence
					observedAt
					ruleVersion
					ruleSource
					createdAt
					updatedAt
				}
				finding {
					id
					referenceId
					kind
					priority
					status
				}
			}
		}
	`;

	const responseData = await proboApiRequest.call(this, mutation, { input });

	return {
		json: responseData,
		pairedItem: { item: itemIndex },
	};
}
