# supabase-config-app

The default `supabase init` config.toml with `double_confirm_changes = false` and
`jwt_expiry = 604800`; `site_url` stays local.

Expected result: exactly `security_config/supabase-email-change-unconfirmed` and
`security_config/supabase-long-jwt-expiry`. The four template-default rules (email
confirmation, 6-character minimum, no CAPTCHA, secure password change) stay silent
because `site_url` is local, and the `env(...)` secret references produce no secret
findings. Do not "fix" the sample.
