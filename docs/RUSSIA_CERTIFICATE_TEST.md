# Russian certificate enrollment test

I use this unreleased branch to test the certificate flow used by the Russian Android mobile app. It targets the vehicle-discovery failure in [issue #54](https://github.com/moryoav/ha-gwm-ev/issues/54). The integration still reports version 0.18.0.

I found that Android 2.4.1 uses the bundled general certificate on a separate enrollment gateway. It submits a certificate signing request and uses the issued certificate on the private vehicle gateway. Anonymous tests reproduced the reported certificate-error HTML when the general certificate was sent directly to the private gateway. Oleg confirmed sign-in and restart recovery with the earlier test build. I still need confirmation that session recovery works with his account.

The new option is off by default. Installing this branch alone keeps the existing connection behavior. I keep issued certificates and private keys in Home Assistant's existing private, account-bound storage. I exclude them from diagnostics and logs. Existing saved sessions without a certificate remain readable. The test reuses a valid certificate after restart and renews it when less than 24 hours remain.

## Install and enable the test

1. Download the ZIP linked in my issue comment and extract it. Find `custom_components/gwm_ora` inside the extracted folder.
2. Move `/config/custom_components/gwm_ora` outside `custom_components` as a backup. Copy the ZIP's `gwm_ora` folder to `/config/custom_components/`. Keep the existing GWM entry and settings.
3. Restart Home Assistant.
4. Open **Settings > Devices & services > GWM**, open the entry's three-dot menu, and choose **Reconfigure**. Select **Russia**. Use the same dedicated account's email and enable **Test Russian certificate enrollment**. Complete verification if GWM asks for it. If Home Assistant asks for reauthentication, that prompt keeps the saved enrollment setting and asks only for the password. If enrollment was not already enabled, reconfigure the entry afterward and enable the option there.
5. Check whether the vehicle appears and its readings update. Wait for at least two normal polling cycles. Use a read-only test and leave vehicle controls alone.
6. If that works, restart Home Assistant again. Check that readings resume without another verification code or certificate-enrollment request. Keep the Android mobile app signed out of the dedicated Home Assistant account during this test.

## Rejected Russian sessions

I found that the Russian Android mobile app treats codes `607501` (another device signed in) and `570062` (protocol changed) as invalid sessions. This build stops using those sessions and requests reauthentication. It does not automatically refresh them, sign in with the password in the background, or replay a vehicle command. Normal access-token expiry still uses the existing refresh path.

Before trying a fresh Home Assistant sign-in, sign in to that exact dedicated account in the GWM Android mobile app. Complete any pending profile, verification, or agreement prompts, then sign out of that account in the Android mobile app. A separate account for normal phone use avoids competing logins. The code alone does not prove which prompt, if any, is outstanding.

An explicit Home Assistant sign-in can replace rejected tokens and reuse a usable enrolled certificate. Connection timeouts and phone-login code `307999` remain separate problems; this change does not establish their cause.

## Report the result

I need to know whether reconfiguration, fresh readings, restart recovery, and the Android mobile app worked. If a step fails, include the exact step and time.

For logs, open **Settings > System > Logs**, select **Home Assistant Core** if prompted, and choose **Show raw logs**. Share the lines around the attempt containing:

```text
GWM Russia certificate test
GWM authentication diagnostic
stage=vehicle_discovery
GWM cloud
```

The enrollment warnings report when it starts and whether it succeeds. Failures include a safe category, HTTP status, and numeric GWM error code where available. Enable GWM debug logging before reconfiguration if a more detailed capture is needed. Review the excerpt for private details before posting. Do not share passwords, verification codes, tokens, VINs, private storage files, certificates, or private keys.

## Return to the released integration

While the test build is still installed, reconfigure the same Russian account with **Test Russian certificate enrollment** unchecked. This removes the optional certificate from the saved authentication state after successful authentication. Then restore the backed-up `gwm_ora` folder and restart Home Assistant.

The released connection may still have the original gateway error. If reconfiguration fails, keep the backup and report the failure before removing any private state or deleting the entry.
