# Signing Barry's builds

Unsigned programs get warnings: Windows SmartScreen says it "protected your PC", and macOS asks people to right-click and choose **Open**. Signing removes those warnings, and antivirus products trust signed programs more.

The build workflow (`.github/workflows/build.yml`) already has the signing steps. Each one stays switched off until its secrets exist in the repository, under **Settings > Secrets and variables > Actions**. Nothing else needs to change.

## Windows: Microsoft Artifact Signing

Artifact Signing (formerly Trusted Signing) costs about US$10 a month. Microsoft checks your identity before it issues a certificate, so check that you're eligible in your country first.

1. In the Azure portal, create an **Artifact Signing account** and a **certificate profile** (Public Trust).
2. Complete the identity validation Microsoft asks for.
3. Create an **app registration** (Microsoft Entra ID > App registrations), add a client secret, and give the app the **Artifact Signing Certificate Profile Signer** role on the signing account.
4. Add these repository secrets:

| Secret | Where to find it |
|---|---|
| `AZURE_TENANT_ID` | App registration > Overview > Directory (tenant) ID |
| `AZURE_CLIENT_ID` | App registration > Overview > Application (client) ID |
| `AZURE_CLIENT_SECRET` | The client secret you created |
| `AZURE_SIGNING_ENDPOINT` | Signing account > Overview > Account URI, for example `https://weu.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | The signing account's name |
| `AZURE_SIGNING_PROFILE` | The certificate profile's name |

From then on, every build signs `BarryBear.exe` before it's zipped, and signs the installer after Inno Setup builds it.

A free alternative for open-source projects is the [SignPath Foundation](https://signpath.org). They sign with their own certificate after reviewing the project, and use a different workflow step. Ask Claude to switch the workflow over if they accept Barry.

## macOS: Developer ID and notarisation

This needs the Apple Developer Program (US$99 a year).

1. In Xcode or on developer.apple.com, create a **Developer ID Application** certificate.
2. Export it with its private key as a `.p12` file with a password, then convert it to text: `base64 -i barry.p12 | pbcopy`.
3. At appleid.apple.com, create an **app-specific password**.
4. Add these repository secrets:

| Secret | What it is |
|---|---|
| `MAC_CERTIFICATE_P12` | The base64 text of the `.p12` file |
| `MAC_CERTIFICATE_PASSWORD` | The password you exported it with |
| `MAC_SIGNING_IDENTITY` | The certificate's full name, for example `Developer ID Application: Your Name (TEAMID1234)` |
| `APPLE_ID` | Your Apple ID email |
| `APPLE_TEAM_ID` | Your 10-character team ID |
| `APPLE_APP_PASSWORD` | The app-specific password |

The Mac builds then sign the app with the hardened runtime (`packaging/entitlements.plist`), sign the disk image, send it to Apple for notarisation and staple the result. Notarised copies open without the right-click step. Barry's in-app updates also work better once the app is signed.

## After signing is set up

Run the **Build** workflow by hand (Actions > Build > Run workflow) to check that signing works before the next tagged release. Windows shows the signer under the file's **Properties > Digital Signatures**. On a Mac, `spctl -a -vv "Barry Bear.app"` should say "accepted, source=Notarized Developer ID".
