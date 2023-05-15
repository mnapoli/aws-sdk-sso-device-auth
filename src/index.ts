import {
    CreateTokenCommand,
    CreateTokenCommandOutput,
    RegisterClientCommand,
    SSOOIDCClient,
    StartDeviceAuthorizationCommand,
} from '@aws-sdk/client-sso-oidc';
import { AwsCredentialIdentity } from '@aws-sdk/types';
import { GetRoleCredentialsCommand, SSOClient } from '@aws-sdk/client-sso';

export type SsoParams = {
    startUrl: string;
    accountId: string;
    region: string;
    roleName: string;
};

export async function resolveSsoCredentials(
    profile: SsoParams,
    options: {
        clientName: string;
        openUrl: (url: string) => Promise<void>;
    }
): Promise<AwsCredentialIdentity> {
    const ssoOidc = new SSOOIDCClient({
        region: profile.region,
    });
    const sso = new SSOClient({
        region: profile.region,
    });

    const client = await ssoOidc.send(
        new RegisterClientCommand({
            clientName: options.clientName,
            clientType: 'public',
        })
    );

    const auth = await ssoOidc.send(
        new StartDeviceAuthorizationCommand({
            clientId: client.clientId,
            clientSecret: client.clientSecret,
            startUrl: profile.startUrl,
        })
    );
    if (!auth.verificationUriComplete) {
        throw new Error('Unexpected error: AWS SSO did not return a verification URL');
    }

    await options.openUrl(auth.verificationUriComplete);

    let token: CreateTokenCommandOutput | undefined;
    while (true) {
        await sleep(1000);
        try {
            token = await ssoOidc.send(
                new CreateTokenCommand({
                    clientId: client.clientId,
                    clientSecret: client.clientSecret,
                    deviceCode: auth.deviceCode,
                    grantType: 'urn:ietf:params:oauth:grant-type:device_code',
                })
            );
            break;
        } catch (e) {
            if (e.name !== 'AuthorizationPendingException') {
                throw e;
            }
        }
    }

    // Get role credentials
    const { roleCredentials } = await sso.send(
        new GetRoleCredentialsCommand({
            accountId: profile.accountId,
            roleName: profile.roleName,
            accessToken: token.accessToken,
        })
    );
    if (!roleCredentials?.accessKeyId || !roleCredentials.secretAccessKey) {
        throw new Error('Unexpected error: no role credentials returned by the AWS SSO API');
    }

    return {
        accessKeyId: roleCredentials.accessKeyId,
        secretAccessKey: roleCredentials.secretAccessKey,
        sessionToken: roleCredentials.sessionToken,
    };
}

async function sleep(number: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, number));
}
