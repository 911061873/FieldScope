<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">工作台概览</h1>
        <p class="page-subtitle">
          欢迎回来，{{ auth.user?.display_name || auth.user?.username }}。查看平台接入与数据面调用状态。
        </p>
      </div>
      <n-button secondary @click="loadStats" :loading="loading">刷新数据</n-button>
    </div>

    <n-grid cols="1 s:2 m:4" responsive="screen" :x-gap="16" :y-gap="16" style="margin-bottom: 18px">
      <n-gi>
        <div class="surface-card stat-card">
          <div class="stat-label">已接入三方平台</div>
          <div class="stat-value">{{ counts.platforms }}</div>
          <div class="stat-sub">API + 远端 MCP 协议</div>
        </div>
      </n-gi>
      <n-gi>
        <div class="surface-card stat-card">
          <div class="stat-label">外部数据角色</div>
          <div class="stat-value">{{ counts.externalRoles }}</div>
          <div class="stat-sub">控制平台 / 接口 / 数据范围 / 字段</div>
        </div>
      </n-gi>
      <n-gi>
        <div class="surface-card stat-card">
          <div class="stat-label">数据面调用总数</div>
          <div class="stat-value">{{ auditStats.total }}</div>
          <div class="stat-sub">
            HTTP {{ auditStats.http_calls }} · MCP {{ auditStats.mcp_calls }}
          </div>
        </div>
      </n-gi>
      <n-gi>
        <div class="surface-card stat-card">
          <div class="stat-label">放行 / 拦截 / 异常</div>
          <div class="stat-value">
            <span style="color: #0f766e">{{ auditStats.allowed }}</span>
            <span class="stat-sep">/</span>
            <span style="color: #d97706">{{ auditStats.denied }}</span>
            <span class="stat-sep">/</span>
            <span style="color: #dc2626">{{ auditStats.errors }}</span>
          </div>
          <div class="stat-sub">元数据审计实时统计</div>
        </div>
      </n-gi>
    </n-grid>

    <n-grid cols="1 m:2" responsive="screen" :x-gap="16" :y-gap="16">
      <n-gi>
        <div class="surface-card">
          <h2 class="section-title">数据面接入端点</h2>
          <n-descriptions label-placement="top" :column="1" bordered size="small">
            <n-descriptions-item label="HTTP 反向代理网关">
              <code class="mono-code">{{ origin }}/gateway/{platform_code}/{endpoint_path}</code>
            </n-descriptions-item>
            <n-descriptions-item label="MCP Streamable HTTP 网关（AI Agent 接入）">
              <code class="mono-code">POST {{ origin }}/mcp</code>
            </n-descriptions-item>
            <n-descriptions-item label="身份自检接口">
              <code class="mono-code">GET {{ origin }}/api/v1/data-plane/whoami</code>
            </n-descriptions-item>
          </n-descriptions>
        </div>
      </n-gi>

      <n-gi>
        <div class="surface-card">
          <h2 class="section-title">两种数据面认证方式</h2>
          <n-space vertical :size="12">
            <div class="guide-block">
              <div class="guide-title">1. 用户个人 API Key（推荐用于 AI / MCP Client 直连）</div>
              <code class="mono-code">Authorization: Bearer fs_usr_xxxxxxxx</code>
            </div>
            <div class="guide-block">
              <div class="guide-title">2. 外部应用代调用（推荐用于第三方业务系统集成）</div>
              <code class="mono-code">Authorization: Bearer fs_app_xxxxxxxx</code><br />
              <code class="mono-code">X-FieldScope-User: alice</code>
            </div>
          </n-space>
        </div>
      </n-gi>
    </n-grid>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { NButton, NDescriptions, NDescriptionsItem, NGi, NGrid, NSpace } from "naive-ui";
import { apiRequest } from "@/api/client";
import type { AuditStats, ExternalRole, PlatformItem } from "@/api/types";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const loading = ref(false);
const origin = window.location.origin;

const counts = reactive({
  platforms: 0,
  externalRoles: 0,
});

const auditStats = reactive<AuditStats>({
  total: 0,
  allowed: 0,
  denied: 0,
  errors: 0,
  http_calls: 0,
  mcp_calls: 0,
});

async function loadStats() {
  loading.value = true;
  try {
    const tasks: Promise<void>[] = [];
    if (auth.hasPermission("platform:read")) {
      tasks.push(
        apiRequest<PlatformItem[]>("/api/v1/admin/platforms").then((res) => {
          counts.platforms = res.length;
        })
      );
    }
    if (auth.hasPermission("external_role:read")) {
      tasks.push(
        apiRequest<ExternalRole[]>("/api/v1/admin/external-roles").then((res) => {
          counts.externalRoles = res.length;
        })
      );
    }
    if (auth.hasPermission("audit:read")) {
      tasks.push(
        apiRequest<AuditStats>("/api/v1/admin/audit-logs/stats").then((res) => {
          Object.assign(auditStats, res);
        })
      );
    }
    await Promise.allSettled(tasks);
  } finally {
    loading.value = false;
  }
}

onMounted(loadStats);
</script>

<style scoped>
.stat-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.stat-label {
  font-size: 13px;
  color: var(--fs-text-muted);
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--fs-text);
}

.stat-sep {
  margin: 0 4px;
  color: #cbd5e1;
  font-weight: 400;
}

.stat-sub {
  font-size: 12px;
  color: var(--fs-text-muted);
}

.section-title {
  margin: 0 0 14px;
  font-size: 15px;
  font-weight: 600;
}

.guide-block {
  padding: 12px 14px;
  background: #f8fafc;
  border: 1px solid var(--fs-border);
  border-radius: 8px;
  line-height: 1.7;
}

.guide-title {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 4px;
}
</style>
