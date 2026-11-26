export interface RoleBrief {
  id: number;
  code: string;
  name: string;
}

export interface CurrentUser {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  department: string | null;
  attributes: Record<string, unknown>;
  is_active: boolean;
  is_superuser: boolean;
  platform_roles: RoleBrief[];
  external_roles: RoleBrief[];
  platform_permissions: string[];
}

export interface PlatformPermission {
  id: number;
  code: string;
  name: string;
  module: string;
  description: string;
}

export interface PlatformRole {
  id: number;
  code: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions: PlatformPermission[];
  created_at: string;
  updated_at: string;
}

export interface UserItem {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  department: string | null;
  attributes: Record<string, unknown>;
  is_active: boolean;
  is_superuser: boolean;
  platform_roles: RoleBrief[];
  external_roles: RoleBrief[];
  created_at: string;
  updated_at: string;
}

export interface UserApiKey {
  id: number;
  user_id: number;
  name: string;
  key_prefix: string;
  expires_at: string | null;
  last_used_at: string | null;
  is_active: boolean;
  created_at: string;
  plain_key?: string;
}

export interface ExternalApp {
  id: number;
  app_code: string;
  name: string;
  description: string;
  key_prefix: string;
  user_identity_header: string;
  allowed_user_ids: number[];
  allowed_external_role_ids: number[];
  last_used_at: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  plain_key?: string;
}

export interface PlatformEndpoint {
  id: number;
  platform_id: number;
  resource_type: "http_endpoint" | "mcp_tool";
  code: string;
  name: string;
  description: string;
  method: string | null;
  path_pattern: string | null;
  expose_as_mcp: boolean;
  mcp_tool_name: string | null;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface PlatformItem {
  id: number;
  code: string;
  name: string;
  description: string;
  protocol_type: "api" | "mcp";
  base_url: string;
  mcp_transport: "streamable_http" | null;
  timeout_ms: number;
  extra_headers: Record<string, string>;
  is_active: boolean;
  endpoints: PlatformEndpoint[];
  created_at: string;
  updated_at: string;
}

export interface PlatformAuthConfigRead {
  platform_id: number;
  auth_type: "none" | "static" | "oauth2" | "custom_http";
  config: Record<string, any>;
  updated_at: string | null;
}

export interface PlatformTokenStatus {
  platform_id: number;
  auth_type: string;
  has_access_token: boolean;
  has_refresh_token: boolean;
  token_preview: string | null;
  token_type: string | null;
  expires_at: string | null;
  is_expired: boolean;
  last_refreshed_at: string | null;
  last_error: string | null;
}

export interface PlatformAuthTestResult {
  ok: boolean;
  upstream_status: number;
  retried_after_refresh: boolean;
  latency_ms: number;
  response_preview: unknown;
  error: string | null;
}

export interface ExternalPolicy {
  id: number;
  external_role_id: number;
  platform_id: number;
  endpoint_id: number | null;
  name: string;
  effect: "allow" | "deny";
  priority: number;
  request_rules: {
    validate?: Array<{ expr: string; message: string }>;
    enforce?: Record<string, unknown>;
  };
  row_filter: { list_path: string; expr: string } | null;
  field_rules: {
    mode: "allowlist" | "denylist";
    fields: string[];
    transforms: Array<{ path: string; action: string }>;
  } | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ExternalRole {
  id: number;
  code: string;
  name: string;
  description: string;
  is_active: boolean;
  policies: ExternalPolicy[];
  created_at: string;
  updated_at: string;
}

export interface AuditLogItem {
  id: number;
  trace_id: string;
  user_id: number | null;
  username: string | null;
  app_id: number | null;
  app_code: string | null;
  protocol: string;
  platform_code: string;
  endpoint_code: string | null;
  decision: "allow" | "deny" | "error";
  matched_policy_ids: number[];
  enforced_params: Record<string, unknown>;
  rows_before: number | null;
  rows_after: number | null;
  pruned_fields: string[];
  transformed_fields: string[];
  upstream_status: number | null;
  latency_ms: number;
  error_message: string | null;
  created_at: string;
}

export interface AuditLogPage {
  total: number;
  items: AuditLogItem[];
}

export interface AuditStats {
  total: number;
  allowed: number;
  denied: number;
  errors: number;
  http_calls: number;
  mcp_calls: number;
}
