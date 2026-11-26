<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">三方平台接入</h1>
        <p class="page-subtitle">
          统一接入第三方 REST API 与远端 MCP 服务，配置静态授权、标准 OAuth2 或自定义 HTTP Token 自动续期。
        </p>
      </div>
      <n-button v-if="canWrite" type="primary" @click="openCreatePlatform">接入新平台</n-button>
    </div>

    <div class="surface-card">
      <n-data-table :columns="columns" :data="platforms" :loading="loading" :bordered="false" />
    </div>

    <!-- Create / Edit Platform Modal -->
    <n-modal
      v-model:show="showPlatformModal"
      preset="card"
      :title="editingPlatform ? `编辑平台：${editingPlatform.code}` : '接入三方平台'"
      style="width: 560px"
    >
      <n-form label-placement="top">
        <n-grid :cols="2" :x-gap="14">
          <n-gi>
            <n-form-item label="平台编码 (唯一标识)" required>
              <n-input
                v-model:value="platformForm.code"
                :disabled="Boolean(editingPlatform)"
                placeholder="例如 jira / crm / hr_mcp"
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="平台名称" required>
              <n-input v-model:value="platformForm.name" placeholder="例如 企业 CRM 系统" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="接入协议" required>
              <n-select
                v-model:value="platformForm.protocol_type"
                :disabled="Boolean(editingPlatform)"
                :options="[
                  { label: 'REST API 平台', value: 'api' },
                  { label: '远端 MCP Server', value: 'mcp' },
                ]"
              />
            </n-form-item>
          </n-gi>
          <n-gi v-if="platformForm.protocol_type === 'mcp'">
            <n-form-item label="MCP 传输模式">
              <n-select
                v-model:value="platformForm.mcp_transport"
                :options="[{ label: 'Streamable HTTP', value: 'streamable_http' }]"
              />
            </n-form-item>
          </n-gi>
          <n-gi v-else>
            <n-form-item label="超时时间 (ms)">
              <n-input-number v-model:value="platformForm.timeout_ms" :min="500" :max="300000" style="width: 100%" />
            </n-form-item>
          </n-gi>
        </n-grid>
        <n-form-item label="基础地址 (Base URL)" required>
          <n-input v-model:value="platformForm.base_url" placeholder="https://api.example.com" />
        </n-form-item>
        <n-form-item label="附加请求头 JSON (extra_headers，可选)">
          <n-input
            v-model:value="platformForm.extraHeadersJson"
            type="textarea"
            :rows="2"
            class="mono-code"
            placeholder='{"X-Tenant": "acme"}'
          />
        </n-form-item>
        <n-form-item label="说明">
          <n-input v-model:value="platformForm.description" type="textarea" :rows="2" />
        </n-form-item>
        <n-form-item label="启用状态" label-placement="left">
          <n-switch v-model:value="platformForm.is_active" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showPlatformModal = false">取消</n-button>
          <n-button type="primary" :loading="savingPlatform" @click="handleSavePlatform">保存</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- Auth & Renewal Configuration Drawer -->
    <n-drawer v-model:show="showAuthDrawer" :width="680">
      <n-drawer-content :title="`认证与续期配置：${activePlatform?.name || ''}`">
        <n-tabs type="line" animated>
          <n-tab-pane name="config" tab="认证配置">
            <n-form label-placement="top" style="margin-top: 8px">
              <n-form-item label="认证模式">
                <n-radio-group v-model:value="authType">
                  <n-radio-button value="none">无认证</n-radio-button>
                  <n-radio-button value="static">静态授权</n-radio-button>
                  <n-radio-button value="oauth2">动态 · 标准 OAuth2</n-radio-button>
                  <n-radio-button value="custom_http">动态 · 自定义 HTTP</n-radio-button>
                </n-radio-group>
              </n-form-item>

              <!-- Static Auth -->
              <template v-if="authType === 'static'">
                <n-grid :cols="2" :x-gap="14">
                  <n-gi>
                    <n-form-item label="传递位置" required>
                      <n-select
                        v-model:value="staticForm.location"
                        :options="[
                          { label: '请求头 (Header)', value: 'header' },
                          { label: '请求参数 (Query)', value: 'query' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="参数 / Header 名称" required>
                      <n-input v-model:value="staticForm.param_name" placeholder="Authorization / api_key" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="值前缀（可选）">
                      <n-input v-model:value="staticForm.value_prefix" placeholder="例如 Bearer （注意空格）" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="密钥 / Token 值（加密存储）" required>
                      <n-input
                        v-model:value="staticForm.value"
                        type="password"
                        show-password-on="click"
                        placeholder="保留 ******** 表示不修改原密钥"
                      />
                    </n-form-item>
                  </n-gi>
                </n-grid>
              </template>

              <!-- Standard OAuth2 -->
              <template v-if="authType === 'oauth2'">
                <n-grid :cols="2" :x-gap="14">
                  <n-gi>
                    <n-form-item label="OAuth 授权模式">
                      <n-select
                        v-model:value="oauthForm.grant_type"
                        :options="[
                          { label: '客户端凭证 (client_credentials)', value: 'client_credentials' },
                          { label: '管理员授权码 (authorization_code)', value: 'authorization_code' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="客户端凭据传递方式">
                      <n-select
                        v-model:value="oauthForm.client_auth_method"
                        :options="[
                          { label: 'Form Body', value: 'body' },
                          { label: 'HTTP Basic Header', value: 'basic' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="Client ID" required>
                      <n-input v-model:value="oauthForm.client_id" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="Client Secret（加密存储）" required>
                      <n-input v-model:value="oauthForm.client_secret" type="password" show-password-on="click" />
                    </n-form-item>
                  </n-gi>
                </n-grid>
                <n-form-item label="Token URL" required>
                  <n-input v-model:value="oauthForm.token_url" placeholder="https://idp.example.com/oauth/token" />
                </n-form-item>
                <n-form-item v-if="oauthForm.grant_type === 'authorization_code'" label="Authorize URL" required>
                  <n-input v-model:value="oauthForm.authorize_url" placeholder="https://idp.example.com/oauth/authorize" />
                </n-form-item>
                <n-form-item v-if="oauthForm.grant_type === 'authorization_code'" label="Redirect URI">
                  <n-input v-model:value="oauthForm.redirect_uri" placeholder="https://your-host/oauth/callback" />
                </n-form-item>
                <n-grid :cols="3" :x-gap="12">
                  <n-gi>
                    <n-form-item label="Scopes（空格分隔）">
                      <n-input v-model:value="oauthForm.scopesText" placeholder="read write" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="注入位置">
                      <n-select
                        v-model:value="oauthForm.inject_location"
                        :options="[
                          { label: 'Header', value: 'header' },
                          { label: 'Query', value: 'query' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="提前续期 (秒)">
                      <n-input-number v-model:value="oauthForm.refresh_leeway_seconds" :min="0" :max="3600" style="width: 100%" />
                    </n-form-item>
                  </n-gi>
                </n-grid>
                <n-grid :cols="2" :x-gap="12">
                  <n-gi>
                    <n-form-item label="注入参数名">
                      <n-input v-model:value="oauthForm.inject_name" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="注入前缀">
                      <n-input v-model:value="oauthForm.inject_prefix" />
                    </n-form-item>
                  </n-gi>
                </n-grid>
                <n-form-item :show-label="false">
                  <TokenInvalidRulesEditor
                    v-model="oauthForm.invalid_rules"
                    @valid-change="oauthInvalidRulesValid = $event"
                  />
                </n-form-item>
              </template>

              <!-- Custom HTTP Token -->
              <template v-if="authType === 'custom_http'">
                <n-grid :cols="3" :x-gap="12">
                  <n-gi>
                    <n-form-item label="请求方法">
                      <n-select
                        v-model:value="customForm.method"
                        :options="[
                          { label: 'POST', value: 'POST' },
                          { label: 'GET', value: 'GET' },
                          { label: 'PUT', value: 'PUT' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi :span="2">
                    <n-form-item label="获取 Token 请求 URL" required>
                      <n-input v-model:value="customForm.url" placeholder="https://api.example.com/auth/token" />
                    </n-form-item>
                  </n-gi>
                </n-grid>
                <n-grid :cols="2" :x-gap="12">
                  <n-gi>
                    <n-form-item label="Body 类型">
                      <n-select
                        v-model:value="customForm.body_type"
                        :options="[
                          { label: 'JSON', value: 'json' },
                          { label: 'Form', value: 'form' },
                          { label: 'None', value: 'none' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="提前续期 (秒)">
                      <n-input-number v-model:value="customForm.refresh_leeway_seconds" :min="0" :max="3600" style="width: 100%" />
                    </n-form-item>
                  </n-gi>
                </n-grid>
                <n-form-item label="请求体 JSON（可用 {{ secret.xxx }} 引用下方加密变量）">
                  <n-input v-model:value="customForm.bodyJson" type="textarea" :rows="3" class="mono-code" />
                </n-form-item>
                <n-form-item label="加密变量 Secrets JSON（入库 AES-256-GCM 加密，读取脱敏）">
                  <n-input v-model:value="customForm.secretsJson" type="textarea" :rows="2" class="mono-code" />
                </n-form-item>
                <n-grid :cols="2" :x-gap="12">
                  <n-gi>
                    <n-form-item label="Access Token JSONPath" required>
                      <n-input v-model:value="customForm.access_token_path" placeholder="$.data.access_token" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="过期秒数 JSONPath（可选）">
                      <n-input v-model:value="customForm.expires_in_path" placeholder="$.data.expires_in" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="注入位置">
                      <n-select
                        v-model:value="customForm.inject_location"
                        :options="[
                          { label: 'Header', value: 'header' },
                          { label: 'Query', value: 'query' },
                        ]"
                      />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="注入参数名">
                      <n-input v-model:value="customForm.inject_name" placeholder="Authorization / access_token" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="注入前缀">
                      <n-input v-model:value="customForm.inject_prefix" placeholder="Bearer 或留空" />
                    </n-form-item>
                  </n-gi>
                  <n-gi>
                    <n-form-item label="固定兜底 TTL (秒，可选)">
                      <n-input-number v-model:value="customForm.fixed_ttl_seconds" :min="1" style="width: 100%" />
                    </n-form-item>
                  </n-gi>
                </n-grid>
                <n-form-item :show-label="false">
                  <TokenInvalidRulesEditor
                    v-model="customForm.invalid_rules"
                    @valid-change="customInvalidRulesValid = $event"
                  />
                </n-form-item>
              </template>

              <n-space justify="end" style="margin-top: 12px">
                <n-button v-if="canWrite" type="primary" :loading="savingAuth" @click="handleSaveAuth">
                  保存认证配置
                </n-button>
              </n-space>
            </n-form>
          </n-tab-pane>

          <n-tab-pane name="status" tab="Token 状态与测试">
            <n-space vertical :size="16" style="margin-top: 8px">
              <n-descriptions bordered :column="2" size="small" v-if="tokenStatus">
                <n-descriptions-item label="认证类型">{{ tokenStatus.auth_type }}</n-descriptions-item>
                <n-descriptions-item label="Access Token">
                  <n-tag :type="tokenStatus.has_access_token && !tokenStatus.is_expired ? 'success' : 'warning'" size="small" :bordered="false">
                    {{ tokenStatus.has_access_token ? (tokenStatus.is_expired ? '已过期' : '有效') : '未获取' }}
                  </n-tag>
                </n-descriptions-item>
                <n-descriptions-item label="Token 预览">
                  <code class="mono-code">{{ tokenStatus.token_preview || "-" }}</code>
                </n-descriptions-item>
                <n-descriptions-item label="Refresh Token">
                  {{ tokenStatus.has_refresh_token ? "已保存" : "无" }}
                </n-descriptions-item>
                <n-descriptions-item label="过期时间">
                  {{ tokenStatus.expires_at ? new Date(tokenStatus.expires_at).toLocaleString() : "-" }}
                </n-descriptions-item>
                <n-descriptions-item label="最近刷新">
                  {{ tokenStatus.last_refreshed_at ? new Date(tokenStatus.last_refreshed_at).toLocaleString() : "-" }}
                </n-descriptions-item>
                <n-descriptions-item v-if="tokenStatus.last_error" label="最近错误" :span="2">
                  <span style="color: #dc2626">{{ tokenStatus.last_error }}</span>
                </n-descriptions-item>
              </n-descriptions>

              <n-space>
                <n-button secondary @click="loadTokenStatus">刷新状态</n-button>
                <n-button
                  v-if="canWrite && (authType === 'oauth2' || authType === 'custom_http')"
                  type="primary"
                  :loading="refreshingToken"
                  @click="handleForceRefresh"
                >
                  强制获取 / 续期 Token
                </n-button>
                <n-button
                  v-if="canWrite && authType === 'oauth2' && oauthForm.grant_type === 'authorization_code'"
                  secondary
                  type="info"
                  @click="handleGenerateOAuthUrl"
                >
                  生成管理员授权链接
                </n-button>
              </n-space>

              <div v-if="oauthAuthorizeUrl" class="surface-card">
                <div style="font-weight: 600; margin-bottom: 8px">OAuth2 授权码完成步骤</div>
                <p style="font-size: 12.5px; color: var(--fs-text-muted); margin: 0 0 8px">
                  1. 在浏览器中打开下方授权链接并同意授权，获取回调 URL 中的 <code>code</code> 参数：
                </p>
                <div class="secret-box" style="margin-bottom: 10px">{{ oauthAuthorizeUrl }}</div>
                <n-space>
                  <n-input v-model:value="oauthCodeInput" placeholder="粘贴回调获得的 code" style="width: 300px" />
                  <n-button type="primary" @click="handleCompleteOAuthCallback">换取并保存 Token</n-button>
                </n-space>
              </div>

              <div class="surface-card">
                <div style="font-weight: 600; margin-bottom: 10px">在线连通性与自动续期测试</div>
                <n-space style="margin-bottom: 10px">
                  <n-select
                    v-model:value="testReq.method"
                    style="width: 100px"
                    :options="[
                      { label: 'GET', value: 'GET' },
                      { label: 'POST', value: 'POST' },
                    ]"
                  />
                  <n-input v-model:value="testReq.path" placeholder="相对路径，例如 /api/v1/ping" style="width: 320px" />
                  <n-button type="primary" :loading="testingAuth" @click="handleTestAuth">发送测试</n-button>
                </n-space>
                <div v-if="testResult">
                  <n-tag :type="testResult.ok ? 'success' : 'error'" size="small" :bordered="false">
                    HTTP {{ testResult.upstream_status }} · {{ testResult.latency_ms }}ms
                    {{ testResult.retried_after_refresh ? "（已触发自动续期重放）" : "" }}
                  </n-tag>
                  <pre class="secret-box" style="margin-top: 8px; max-height: 220px; overflow: auto">{{
                    testResult.error || JSON.stringify(testResult.response_preview, null, 2)
                  }}</pre>
                </div>
              </div>
            </n-space>
          </n-tab-pane>
        </n-tabs>
      </n-drawer-content>
    </n-drawer>

    <!-- Endpoints / MCP Tools Drawer -->
    <n-drawer v-model:show="showEndpointsDrawer" :width="720">
      <n-drawer-content :title="`接口 / MCP 工具管理：${activePlatform?.name || ''}`">
        <n-space style="margin-bottom: 14px" justify="space-between">
          <n-space>
            <n-button
              v-if="canWrite && activePlatform?.protocol_type === 'api'"
              type="primary"
              @click="openCreateEndpoint"
            >
              新增 API 接口
            </n-button>
            <n-button
              v-if="canWrite && activePlatform?.protocol_type === 'mcp'"
              type="primary"
              :loading="syncingMcp"
              @click="handleSyncMcpTools"
            >
              一键同步上游 MCP Tools
            </n-button>
          </n-space>
          <n-tag size="small" :bordered="false">共 {{ activePlatform?.endpoints.length || 0 }} 项</n-tag>
        </n-space>

        <n-data-table
          :columns="endpointColumns"
          :data="activePlatform?.endpoints || []"
          size="small"
          :bordered="false"
        />
      </n-drawer-content>
    </n-drawer>

    <!-- Create / Edit Endpoint Modal -->
    <n-modal
      v-model:show="showEndpointModal"
      preset="card"
      :title="editingEndpoint ? `编辑接口：${editingEndpoint.code}` : '新增 API 接口'"
      style="width: 540px"
    >
      <n-form label-placement="top">
        <n-grid :cols="2" :x-gap="12">
          <n-gi>
            <n-form-item label="接口编码" required>
              <n-input
                v-model:value="epForm.code"
                :disabled="Boolean(editingEndpoint)"
                placeholder="例如 list_customers"
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="接口名称" required>
              <n-input v-model:value="epForm.name" placeholder="例如 查询客户列表" />
            </n-form-item>
          </n-gi>
          <n-gi v-if="!editingEndpoint || editingEndpoint.resource_type === 'http_endpoint'">
            <n-form-item label="HTTP 方法" required>
              <n-select
                v-model:value="epForm.method"
                :options="['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => ({ label: m, value: m }))"
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="暴露为 MCP Tool" label-placement="left" style="padding-top: 26px">
              <n-switch v-model:value="epForm.expose_as_mcp" />
            </n-form-item>
          </n-gi>
        </n-grid>
        <n-form-item
          v-if="!editingEndpoint || editingEndpoint.resource_type === 'http_endpoint'"
          label="路径模板 (Path Pattern)"
          required
        >
          <n-input v-model:value="epForm.path_pattern" placeholder="例如 /api/v1/customers 或 /api/v1/issue/{key}" />
        </n-form-item>
        <n-form-item v-if="epForm.expose_as_mcp" label="MCP Tool 名称（留空默认 {platform}_{code}）">
          <n-input v-model:value="epForm.mcp_tool_name" placeholder="例如 crm_list_customers" />
        </n-form-item>
        <n-form-item label="描述（供 AI 理解工具用途）">
          <n-input v-model:value="epForm.description" />
        </n-form-item>
        <n-form-item label="入参 JSON Schema">
          <n-input v-model:value="epForm.inputSchemaJson" type="textarea" :rows="3" class="mono-code" />
        </n-form-item>
        <n-form-item label="启用状态" label-placement="left">
          <n-switch v-model:value="epForm.is_active" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showEndpointModal = false">取消</n-button>
          <n-button type="primary" :loading="savingEndpoint" @click="handleSaveEndpoint">保存接口</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from "vue";
import {
  NButton,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NGi,
  NGrid,
  NInput,
  NInputNumber,
  NModal,
  NPopconfirm,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NSpace,
  NSwitch,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import TokenInvalidRulesEditor, {
  type TokenInvalidRulesValue,
} from "@/components/TokenInvalidRulesEditor.vue";
import type {
  PlatformAuthConfigRead,
  PlatformAuthTestResult,
  PlatformEndpoint,
  PlatformItem,
  PlatformTokenStatus,
} from "@/api/types";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const message = useMessage();
const canWrite = computed(() => auth.hasPermission("platform:write"));

const loading = ref(false);
const platforms = ref<PlatformItem[]>([]);

const showPlatformModal = ref(false);
const savingPlatform = ref(false);
const editingPlatform = ref<PlatformItem | null>(null);
const platformForm = reactive({
  code: "",
  name: "",
  description: "",
  protocol_type: "api" as "api" | "mcp",
  base_url: "",
  mcp_transport: "streamable_http" as "streamable_http",
  timeout_ms: 15000,
  extraHeadersJson: "{}",
  is_active: true,
});

// Auth Drawer State
const showAuthDrawer = ref(false);
const activePlatform = ref<PlatformItem | null>(null);
const savingAuth = ref(false);
const authType = ref<"none" | "static" | "oauth2" | "custom_http">("none");
const loadedAuthConfig = ref<Record<string, any> | null>(null);
const oauthInvalidRulesValid = ref(true);
const customInvalidRulesValid = ref(true);

const staticForm = reactive({
  location: "header" as "header" | "query",
  param_name: "Authorization",
  value: "",
  value_prefix: "Bearer ",
});

const oauthForm = reactive({
  grant_type: "client_credentials" as "client_credentials" | "authorization_code",
  client_id: "",
  client_secret: "",
  token_url: "",
  authorize_url: "",
  redirect_uri: "",
  scopesText: "",
  client_auth_method: "body" as "body" | "basic",
  inject_location: "header" as "header" | "query",
  inject_name: "Authorization",
  inject_prefix: "Bearer ",
  refresh_leeway_seconds: 60,
  invalid_rules: { http_statuses: [401], body_rules: [] } as TokenInvalidRulesValue,
});

const customForm = reactive({
  method: "POST" as "GET" | "POST" | "PUT",
  url: "",
  body_type: "json" as "json" | "form" | "none",
  bodyJson: "{}",
  secretsJson: "{}",
  access_token_path: "$.access_token",
  expires_in_path: "$.expires_in",
  fixed_ttl_seconds: null as number | null,
  inject_location: "header" as "header" | "query",
  inject_name: "Authorization",
  inject_prefix: "Bearer ",
  refresh_leeway_seconds: 60,
  invalid_rules: { http_statuses: [401], body_rules: [] } as TokenInvalidRulesValue,
});

const tokenStatus = ref<PlatformTokenStatus | null>(null);
const refreshingToken = ref(false);
const oauthAuthorizeUrl = ref("");
const oauthState = ref("");
const oauthCodeInput = ref("");

const testReq = reactive({ method: "GET", path: "" });
const testingAuth = ref(false);
const testResult = ref<PlatformAuthTestResult | null>(null);

// Endpoints Drawer State
const showEndpointsDrawer = ref(false);
const showEndpointModal = ref(false);
const editingEndpoint = ref<PlatformEndpoint | null>(null);
const savingEndpoint = ref(false);
const syncingMcp = ref(false);
const epForm = reactive({
  code: "",
  name: "",
  description: "",
  method: "GET",
  path_pattern: "",
  expose_as_mcp: true,
  mcp_tool_name: "",
  inputSchemaJson: '{"type": "object", "properties": {}}',
  is_active: true,
});

const columns = computed<DataTableColumns<PlatformItem>>(() => [
  { title: "编码", key: "code", render: (r) => h("code", { class: "mono-code" }, r.code) },
  { title: "平台名称", key: "name" },
  {
    title: "协议",
    key: "protocol_type",
    width: 110,
    render: (r) =>
      h(
        NTag,
        { size: "small", type: r.protocol_type === "mcp" ? "info" : "success", bordered: false },
        () => (r.protocol_type === "mcp" ? `MCP (${r.mcp_transport || "http"})` : "REST API")
      ),
  },
  {
    title: "Base URL",
    key: "base_url",
    ellipsis: { tooltip: true },
    render: (r) => h("code", { class: "mono-code" }, r.base_url),
  },
  {
    title: "接口/工具数",
    key: "endpoints",
    width: 100,
    render: (r) => `${r.endpoints.length} 个`,
  },
  {
    title: "操作",
    key: "actions",
    width: 280,
    render: (r) =>
      h(NSpace, { size: 4 }, () => [
        h(
          NButton,
          { size: "small", quaternary: true, type: "primary", onClick: () => openAuthDrawer(r) },
          () => "认证与续期"
        ),
        h(NButton, { size: "small", quaternary: true, onClick: () => openEndpointsDrawer(r) }, () =>
          r.protocol_type === "mcp" ? "MCP 工具" : "接口"
        ),
        canWrite.value
          ? h(NButton, { size: "small", quaternary: true, onClick: () => openEditPlatform(r) }, () => "编辑")
          : null,
        canWrite.value
          ? h(
              NPopconfirm,
              { onPositiveClick: () => handleDeletePlatform(r.id) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                default: () => `确认删除平台「${r.name}」及其全部接口和策略？`,
              }
            )
          : null,
      ]),
  },
]);

const endpointColumns = computed<DataTableColumns<PlatformEndpoint>>(() => [
  { title: "编码", key: "code", render: (r) => h("code", { class: "mono-code" }, r.code) },
  {
    title: "方法 / 路径",
    key: "path_pattern",
    render: (r) =>
      r.resource_type === "mcp_tool"
        ? h(NTag, { size: "small", type: "info", bordered: false }, () => "MCP Tool")
        : h("code", { class: "mono-code" }, `${r.method || "GET"} ${r.path_pattern || ""}`),
  },
  {
    title: "对外 MCP Tool 名",
    key: "mcp_tool_name",
    render: (r) =>
      r.expose_as_mcp ? h("code", { class: "mono-code" }, r.mcp_tool_name || "-") : "未暴露",
  },
  {
    title: "操作",
    key: "actions",
    width: 130,
    render: (r) =>
      canWrite.value
        ? h(NSpace, { size: 4 }, () => [
            h(
              NButton,
              { size: "small", quaternary: true, onClick: () => openEditEndpoint(r) },
              () => "编辑"
            ),
            h(
              NPopconfirm,
              { onPositiveClick: () => handleDeleteEndpoint(r.id) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                default: () => `确认删除「${r.code}」？`,
              }
            ),
          ])
        : "-",
  },
]);

async function loadPlatforms() {
  loading.value = true;
  try {
    platforms.value = await apiRequest<PlatformItem[]>("/api/v1/admin/platforms");
    if (activePlatform.value) {
      const updated = platforms.value.find((p) => p.id === activePlatform.value?.id);
      if (updated) activePlatform.value = updated;
    }
  } catch (err: any) {
    message.error(err?.detail || "加载平台列表失败");
  } finally {
    loading.value = false;
  }
}

function openCreatePlatform() {
  editingPlatform.value = null;
  Object.assign(platformForm, {
    code: "",
    name: "",
    description: "",
    protocol_type: "api",
    base_url: "",
    mcp_transport: "streamable_http",
    timeout_ms: 15000,
    extraHeadersJson: "{}",
    is_active: true,
  });
  showPlatformModal.value = true;
}

function openEditPlatform(row: PlatformItem) {
  editingPlatform.value = row;
  Object.assign(platformForm, {
    code: row.code,
    name: row.name,
    description: row.description,
    protocol_type: row.protocol_type,
    base_url: row.base_url,
    mcp_transport: "streamable_http",
    timeout_ms: row.timeout_ms,
    extraHeadersJson: JSON.stringify(row.extra_headers || {}, null, 2),
    is_active: row.is_active,
  });
  showPlatformModal.value = true;
}

async function handleSavePlatform() {
  let extraHeaders: Record<string, string> = {};
  try {
    const parsed = JSON.parse(platformForm.extraHeadersJson || "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not object");
    }
    extraHeaders = parsed;
  } catch {
    message.error("附加请求头必须是合法的 JSON 对象");
    return;
  }

  savingPlatform.value = true;
  try {
    if (editingPlatform.value) {
      await apiRequest(`/api/v1/admin/platforms/${editingPlatform.value.id}`, {
        method: "PATCH",
        body: {
          name: platformForm.name,
          description: platformForm.description,
          base_url: platformForm.base_url,
          mcp_transport: platformForm.protocol_type === "mcp" ? platformForm.mcp_transport : null,
          timeout_ms: platformForm.timeout_ms,
          extra_headers: extraHeaders,
          is_active: platformForm.is_active,
        },
      });
    } else {
      await apiRequest("/api/v1/admin/platforms", {
        method: "POST",
        body: {
          code: platformForm.code,
          name: platformForm.name,
          description: platformForm.description,
          protocol_type: platformForm.protocol_type,
          base_url: platformForm.base_url,
          mcp_transport: platformForm.protocol_type === "mcp" ? platformForm.mcp_transport : null,
          timeout_ms: platformForm.timeout_ms,
          extra_headers: extraHeaders,
          is_active: platformForm.is_active,
        },
      });
    }
    message.success("平台已保存");
    showPlatformModal.value = false;
    await loadPlatforms();
  } catch (err: any) {
    message.error(err?.detail || "保存失败");
  } finally {
    savingPlatform.value = false;
  }
}

async function handleDeletePlatform(id: number) {
  try {
    await apiRequest(`/api/v1/admin/platforms/${id}`, { method: "DELETE" });
    message.success("已删除");
    await loadPlatforms();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

async function openAuthDrawer(row: PlatformItem) {
  activePlatform.value = row;
  showAuthDrawer.value = true;
  oauthAuthorizeUrl.value = "";
  oauthState.value = "";
  oauthCodeInput.value = "";
  testResult.value = null;
  loadedAuthConfig.value = null;
  oauthInvalidRulesValid.value = true;
  customInvalidRulesValid.value = true;
  oauthForm.invalid_rules = { http_statuses: [401], body_rules: [] };
  customForm.invalid_rules = { http_statuses: [401], body_rules: [] };

  try {
    const cfg = await apiRequest<PlatformAuthConfigRead>(`/api/v1/admin/platforms/${row.id}/auth`);
    authType.value = cfg.auth_type;
    const c = cfg.config || {};
    loadedAuthConfig.value = JSON.parse(JSON.stringify(c));
    if (cfg.auth_type === "static") {
      Object.assign(staticForm, {
        location: c.location || "header",
        param_name: c.param_name || "Authorization",
        value: c.value || "",
        value_prefix: c.value_prefix ?? "",
      });
    } else if (cfg.auth_type === "oauth2") {
      Object.assign(oauthForm, {
        grant_type: c.grant_type || "client_credentials",
        client_id: c.client_id || "",
        client_secret: c.client_secret || "",
        token_url: c.token_url || "",
        authorize_url: c.authorize_url || "",
        redirect_uri: c.redirect_uri || "",
        scopesText: (c.scopes || []).join(" "),
        client_auth_method: c.client_auth_method || "body",
        inject_location: c.inject_location || "header",
        inject_name: c.inject_name || "Authorization",
        inject_prefix: c.inject_prefix ?? "Bearer ",
        refresh_leeway_seconds: c.refresh_leeway_seconds ?? 60,
        invalid_rules: {
          http_statuses: Array.isArray(c.invalid_rules?.http_statuses)
            ? [...c.invalid_rules.http_statuses]
            : [401],
          body_rules: Array.isArray(c.invalid_rules?.body_rules)
            ? JSON.parse(JSON.stringify(c.invalid_rules.body_rules))
            : [],
        },
      });
    } else if (cfg.auth_type === "custom_http") {
      Object.assign(customForm, {
        method: c.token_request?.method || "POST",
        url: c.token_request?.url || "",
        body_type: c.token_request?.body_type || "json",
        bodyJson: JSON.stringify(c.token_request?.body || {}, null, 2),
        secretsJson: JSON.stringify(c.secrets || {}, null, 2),
        access_token_path: c.response_mapping?.access_token_path || "$.access_token",
        expires_in_path: c.response_mapping?.expires_in_path || "$.expires_in",
        fixed_ttl_seconds: c.response_mapping?.fixed_ttl_seconds ?? null,
        inject_location: c.inject_location || "header",
        inject_name: c.inject_name || "Authorization",
        inject_prefix: c.inject_prefix ?? "Bearer ",
        refresh_leeway_seconds: c.refresh_leeway_seconds ?? 60,
        invalid_rules: {
          http_statuses: Array.isArray(c.invalid_rules?.http_statuses)
            ? [...c.invalid_rules.http_statuses]
            : [401],
          body_rules: Array.isArray(c.invalid_rules?.body_rules)
            ? JSON.parse(JSON.stringify(c.invalid_rules.body_rules))
            : [],
        },
      });
    }
    await loadTokenStatus();
  } catch (err: any) {
    message.error(err?.detail || "加载认证配置失败");
  }
}

async function loadTokenStatus() {
  if (!activePlatform.value) return;
  tokenStatus.value = await apiRequest<PlatformTokenStatus>(
    `/api/v1/admin/platforms/${activePlatform.value.id}/auth/token-status`
  );
}

async function handleSaveAuth() {
  if (!activePlatform.value) return;
  if (
    (authType.value === "oauth2" && !oauthInvalidRulesValid.value) ||
    (authType.value === "custom_http" && !customInvalidRulesValid.value)
  ) {
    message.error("Token 失效判定规则 JSON 格式不正确，请先修正");
    return;
  }

  let payload: Record<string, unknown> = { auth_type: "none" };
  const prev =
    loadedAuthConfig.value && loadedAuthConfig.value.auth_type === authType.value
      ? loadedAuthConfig.value
      : {};

  try {
    if (authType.value === "static") {
      payload = { ...prev, auth_type: "static", ...staticForm };
    } else if (authType.value === "oauth2") {
      payload = {
        ...prev,
        auth_type: "oauth2",
        grant_type: oauthForm.grant_type,
        client_id: oauthForm.client_id,
        client_secret: oauthForm.client_secret,
        token_url: oauthForm.token_url,
        authorize_url: oauthForm.authorize_url || null,
        redirect_uri: oauthForm.redirect_uri || null,
        scopes: oauthForm.scopesText.trim() ? oauthForm.scopesText.trim().split(/\s+/) : [],
        client_auth_method: oauthForm.client_auth_method,
        inject_location: oauthForm.inject_location,
        inject_name: oauthForm.inject_name,
        inject_prefix: oauthForm.inject_prefix,
        refresh_leeway_seconds: oauthForm.refresh_leeway_seconds,
        invalid_rules: {
          http_statuses: oauthForm.invalid_rules.http_statuses,
          body_rules: oauthForm.invalid_rules.body_rules,
        },
      };
    } else if (authType.value === "custom_http") {
      const bodyObj = JSON.parse(customForm.bodyJson || "{}");
      const secretsObj = JSON.parse(customForm.secretsJson || "{}");
      payload = {
        ...prev,
        auth_type: "custom_http",
        token_request: {
          ...(prev.token_request || {}),
          method: customForm.method,
          url: customForm.url,
          body_type: customForm.body_type,
          body: bodyObj,
        },
        secrets: secretsObj,
        response_mapping: {
          ...(prev.response_mapping || {}),
          access_token_path: customForm.access_token_path,
          expires_in_path: customForm.expires_in_path || null,
          fixed_ttl_seconds: customForm.fixed_ttl_seconds,
        },
        inject_location: customForm.inject_location,
        inject_name: customForm.inject_name,
        inject_prefix: customForm.inject_prefix,
        refresh_leeway_seconds: customForm.refresh_leeway_seconds,
        invalid_rules: {
          http_statuses: customForm.invalid_rules.http_statuses,
          body_rules: customForm.invalid_rules.body_rules,
        },
      };
    }
  } catch {
    message.error("JSON 字段格式不正确，请检查");
    return;
  }

  savingAuth.value = true;
  try {
    const saved = await apiRequest<PlatformAuthConfigRead>(
      `/api/v1/admin/platforms/${activePlatform.value.id}/auth`,
      {
        method: "PUT",
        body: payload,
      }
    );
    loadedAuthConfig.value = JSON.parse(JSON.stringify(saved.config || {}));
    message.success("认证配置已加密保存");
    await loadTokenStatus();
  } catch (err: any) {
    message.error(err?.detail || "保存认证配置失败");
  } finally {
    savingAuth.value = false;
  }
}

async function handleForceRefresh() {
  if (!activePlatform.value) return;
  refreshingToken.value = true;
  try {
    tokenStatus.value = await apiRequest<PlatformTokenStatus>(
      `/api/v1/admin/platforms/${activePlatform.value.id}/auth/refresh`,
      { method: "POST" }
    );
    message.success("Token 刷新成功");
  } catch (err: any) {
    message.error(err?.detail || "刷新失败");
    await loadTokenStatus();
  } finally {
    refreshingToken.value = false;
  }
}

async function handleGenerateOAuthUrl() {
  if (!activePlatform.value) return;
  try {
    const res = await apiRequest<{ authorize_url: string; state: string }>(
      `/api/v1/admin/platforms/${activePlatform.value.id}/auth/oauth/authorize-url`
    );
    oauthAuthorizeUrl.value = res.authorize_url;
    oauthState.value = res.state;
  } catch (err: any) {
    message.error(err?.detail || "生成授权链接失败");
  }
}

async function handleCompleteOAuthCallback() {
  if (!activePlatform.value || !oauthCodeInput.value.trim()) {
    message.warning("请先填写回调 code");
    return;
  }
  try {
    tokenStatus.value = await apiRequest<PlatformTokenStatus>(
      `/api/v1/admin/platforms/${activePlatform.value.id}/auth/oauth/callback`,
      {
        method: "POST",
        body: { code: oauthCodeInput.value.trim(), state: oauthState.value },
      }
    );
    message.success("OAuth 授权完成，Token 已保存");
    oauthAuthorizeUrl.value = "";
    oauthCodeInput.value = "";
  } catch (err: any) {
    message.error(err?.detail || "换取 Token 失败");
  }
}

async function handleTestAuth() {
  if (!activePlatform.value) return;
  testingAuth.value = true;
  try {
    testResult.value = await apiRequest<PlatformAuthTestResult>(
      `/api/v1/admin/platforms/${activePlatform.value.id}/auth/test`,
      { method: "POST", body: { method: testReq.method, path: testReq.path } }
    );
    await loadTokenStatus();
  } catch (err: any) {
    message.error(err?.detail || "测试调用失败");
  } finally {
    testingAuth.value = false;
  }
}

function openEndpointsDrawer(row: PlatformItem) {
  activePlatform.value = row;
  showEndpointsDrawer.value = true;
}

function openCreateEndpoint() {
  editingEndpoint.value = null;
  Object.assign(epForm, {
    code: "",
    name: "",
    description: "",
    method: "GET",
    path_pattern: "",
    expose_as_mcp: true,
    mcp_tool_name: "",
    inputSchemaJson: '{"type": "object", "properties": {}}',
    is_active: true,
  });
  showEndpointModal.value = true;
}

function openEditEndpoint(ep: PlatformEndpoint) {
  editingEndpoint.value = ep;
  Object.assign(epForm, {
    code: ep.code,
    name: ep.name,
    description: ep.description,
    method: ep.method || "GET",
    path_pattern: ep.path_pattern || "",
    expose_as_mcp: ep.expose_as_mcp,
    mcp_tool_name: ep.mcp_tool_name || "",
    inputSchemaJson: JSON.stringify(ep.input_schema || { type: "object", properties: {} }, null, 2),
    is_active: ep.is_active,
  });
  showEndpointModal.value = true;
}

async function handleSaveEndpoint() {
  if (!activePlatform.value) return;
  let schemaObj: Record<string, unknown> = {};
  try {
    schemaObj = JSON.parse(epForm.inputSchemaJson || "{}");
  } catch {
    message.error("入参 JSON Schema 格式错误");
    return;
  }
  savingEndpoint.value = true;
  try {
    if (editingEndpoint.value) {
      const updateBody: Record<string, unknown> = {
        name: epForm.name,
        description: epForm.description,
        expose_as_mcp: epForm.expose_as_mcp,
        mcp_tool_name: epForm.mcp_tool_name || null,
        input_schema: schemaObj,
        is_active: epForm.is_active,
      };
      if (editingEndpoint.value.resource_type === "http_endpoint") {
        updateBody.method = epForm.method;
        updateBody.path_pattern = epForm.path_pattern;
      }
      await apiRequest(
        `/api/v1/admin/platforms/${activePlatform.value.id}/endpoints/${editingEndpoint.value.id}`,
        { method: "PATCH", body: updateBody }
      );
      message.success("接口已更新");
    } else {
      await apiRequest(`/api/v1/admin/platforms/${activePlatform.value.id}/endpoints`, {
        method: "POST",
        body: {
          resource_type: "http_endpoint",
          code: epForm.code,
          name: epForm.name,
          description: epForm.description,
          method: epForm.method,
          path_pattern: epForm.path_pattern,
          expose_as_mcp: epForm.expose_as_mcp,
          mcp_tool_name: epForm.mcp_tool_name || null,
          input_schema: schemaObj,
          is_active: epForm.is_active,
        },
      });
      message.success("接口已添加");
    }
    showEndpointModal.value = false;
    await loadPlatforms();
  } catch (err: any) {
    message.error(err?.detail || "保存接口失败");
  } finally {
    savingEndpoint.value = false;
  }
}

async function handleDeleteEndpoint(epId: number) {
  if (!activePlatform.value) return;
  try {
    await apiRequest(`/api/v1/admin/platforms/${activePlatform.value.id}/endpoints/${epId}`, {
      method: "DELETE",
    });
    message.success("已删除");
    await loadPlatforms();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

async function handleSyncMcpTools() {
  if (!activePlatform.value) return;
  syncingMcp.value = true;
  try {
    const synced = await apiRequest<PlatformEndpoint[]>(
      `/api/v1/admin/platforms/${activePlatform.value.id}/sync-mcp-tools`,
      { method: "POST" }
    );
    message.success(`同步完成，共发现 ${synced.length} 个 MCP 工具`);
    await loadPlatforms();
  } catch (err: any) {
    message.error(err?.detail || "同步上游 MCP 工具失败");
  } finally {
    syncingMcp.value = false;
  }
}

onMounted(loadPlatforms);
</script>
