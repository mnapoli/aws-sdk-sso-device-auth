import { describe, expect, it } from 'vitest';
import { resolveSsoCredentials } from '../src';
import { mockClient } from 'aws-sdk-client-mock';
import { GetRoleCredentialsCommand, SSOClient } from '@aws-sdk/client-sso';
import {
    CreateTokenCommand,
    RegisterClientCommand,
    SSOOIDCClient,
    StartDeviceAuthorizationCommand,
} from '@aws-sdk/client-sso-oidc';

describe('resolveSsoCredentials', () => {
    it('retrieves access keys', async () => {
        const sso = mockClient(SSOClient);
        sso.reset();
        const ssoOidc = mockClient(SSOOIDCClient);
        ssoOidc.reset();

        ssoOidc
            .on(RegisterClientCommand, {
                clientName: 'test',
                clientType: 'public',
            })
            .resolves({
                clientId: 'client-id',
                clientSecret: 'client-secret',
            });
        ssoOidc
            .on(StartDeviceAuthorizationCommand, {
                clientId: 'client-id',
                clientSecret: 'client-secret',
                startUrl: 'https://start-url.com',
            })
            .resolves({
                verificationUriComplete: 'https://verification-url.com',
                deviceCode: '123456',
            });
        ssoOidc
            .on(CreateTokenCommand, {
                clientId: 'client-id',
                clientSecret: 'client-secret',
                deviceCode: '123456',
                grantType: 'urn:ietf:params:oauth:grant-type:device_code',
            })
            .resolves({
                accessToken: 'access-token',
            });
        sso.on(GetRoleCredentialsCommand, {
            accountId: '123456789012',
            roleName: 'AdministratorAccess',
            accessToken: 'access-token',
        }).resolves({
            roleCredentials: {
                accessKeyId: 'AKIA1234567890',
                secretAccessKey: '1234567890',
                sessionToken: '12345678901234567890',
            },
        });

        expect(
            await resolveSsoCredentials(
                {
                    startUrl: 'https://start-url.com',
                    accountId: '123456789012',
                    roleName: 'AdministratorAccess',
                    region: 'us-east-2',
                },
                {
                    clientName: 'test',
                    openUrl: async (url) => {
                        expect(url).toBe('https://verification-url.com');
                    },
                }
            )
        ).toStrictEqual({
            accessKeyId: 'AKIA1234567890',
            secretAccessKey: '1234567890',
            sessionToken: '12345678901234567890',
        });
    });
});
