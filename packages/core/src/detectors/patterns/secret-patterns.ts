export interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  confidence: "high" | "medium" | "low";
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "sec-openai-key",
    name: "OpenAI API Key",
    regex: /sk-[a-zA-Z0-9]{48}/,
    confidence: "high",
  },
  {
    id: "sec-openai-proj-key",
    name: "OpenAI Project API Key",
    regex: /sk-proj-[a-zA-Z0-9_-]{48}/,
    confidence: "high",
  },
  {
    id: "sec-anthropic-key",
    name: "Anthropic API Key",
    regex: /sk-ant-[a-zA-Z0-9_-]{70,}/,
    confidence: "high",
  },
  {
    id: "sec-stripe-live-secret",
    name: "Stripe Live Secret Key",
    regex: /sk_live_[a-zA-Z0-9]{24,}/,
    confidence: "high",
  },
  {
    id: "sec-stripe-test-secret",
    name: "Stripe Test Secret Key",
    regex: /sk_test_[a-zA-Z0-9]{24,}/,
    confidence: "high",
  },
  {
    id: "sec-aws-access-key",
    name: "AWS Access Key ID",
    regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
    confidence: "high",
  },
  {
    id: "sec-aws-secret-key",
    name: "AWS Secret Access Key",
    regex: /aws_secret_access_key\s*=\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i,
    confidence: "medium",
  },
  {
    id: "sec-github-token",
    name: "GitHub Personal Access Token",
    regex: /gh[pous]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,
    confidence: "high",
  },
  {
    id: "sec-supabase-service-key",
    name: "Supabase Service Role Key",
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
    confidence: "medium",
  },
  {
    id: "sec-slack-bot-token",
    name: "Slack Bot Token",
    regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/,
    confidence: "high",
  },
  {
    id: "sec-generic-jwt",
    name: "JSON Web Token",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    confidence: "low",
  },
  {
    id: "sec-google-gcp-api-key",
    name: "Google Cloud Platform API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/,
    confidence: "high",
  },
  {
    id: "sec-discord-bot-token",
    name: "Discord Bot Token",
    regex: /[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}/,
    confidence: "high",
  },
  {
    id: "sec-sendgrid-api-key",
    name: "SendGrid API Key",
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/,
    confidence: "high",
  },
  {
    id: "sec-mailchimp-api-key",
    name: "Mailchimp API Key",
    regex: /[0-9a-f]{32}-us[0-9]{1,2}/,
    confidence: "high",
  },
  {
    id: "sec-generic-password",
    name: "Generic Password Assignment",
    regex: /(password|passwd|pwd)\s*[:=]\s*['"]([^'"]+)['"]/i,
    confidence: "low",
  },
  {
    id: "sec-generic-secret",
    name: "Generic Secret Assignment",
    regex: /(secret|token|api_key|apikey|access_token)\s*[:=]\s*['"]([^'"]{10,})['"]/i,
    confidence: "low",
  }
];
