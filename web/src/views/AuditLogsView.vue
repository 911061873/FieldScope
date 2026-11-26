<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">审计日志</h1>
        <p class="page-subtitle">记录每一次 HTTP / MCP 数据面调用的权限决策、参数注入、行过滤与字段脱敏元数据。</p>
      </div>
      <n-button secondary @click="loadLogs" :loading="loading">刷新</n-button>
    </div>

    <div class="surface-card" style="margin-bottom: 14px">
      <n-space wrap align="center">
        <n-input v-model:value="filters.username" placeholder="按用户名筛选" clearable style="width: 160px" />
        <n-input v-model:value="filters.platform_code" placeholder="按平台编码筛选" clearable style="width: 160px" />
        <n-select
          v-model:value="filters.protocol"
          clearable
          placeholder="协议"
          :options="protocolOptions"
          style="width: 120px"
        />
        <n-select
          v-model:value="filters.decision"
          clearable
          placeholder="决策结果"
          :options="decisionOptions"
          style="width: 130px"
        />
        <n-button type="primary" @click="handleSearch">查询</n-button>
      </n-space>
    </div>

    <div class="surface-card">
      <n-data-table
        :columns="columns"
        :data="items"
        :loading="loading"
        :bordered="false"
        size="small"
      />
      <div style="display: flex; justify-content: flex-end; margin-top: 14px">
        <n-pagination
          v-model:page="page"
          :page-size="pageSize"
          :item-count="total"
          @update:page="loadLogs"
        />
      </div>
    </div>

    <n-drawer v-model:show="showDetail" :width="560">
      <n-drawer-content title="审计记录详情" v-if="activeItem">
        <n-descriptions :column="1" bordered label-placement="left" size="small">
          <n-descriptions-item label="Trace ID">
            <code class="mono-code">{{ activeItem.trace_id }}</code>
          </n-descriptions-item>
          <n-descriptions-item label="时间">
            {{ new Date(activeItem.created_at).toLocaleString() }}
          </n-descriptions-item>
          <n-descriptions-item label="调用用户">{{ activeItem.username || "-" }}</n-descriptions-item>
          <n-descriptions-item label="代调外部应用">{{ activeItem.app_code || "用户直连" }}</n-descriptions-item>
          <n-descriptions-item label="协议 / 目标">
            {{ activeItem.protocol.toUpperCase() }} · {{ activeItem.platform_code }} /
            {{ activeItem.endpoint_code || "-" }}
          </n-descriptions-item>
          <n-descriptions-item label="决策 / 上游状态 / 耗时">
            {{ activeItem.decision }} · HTTP {{ activeItem.upstream_status ?? "-" }} ·
            {{ activeItem.latency_ms }} ms
          </n-descriptions-item>
          <n-descriptions-item label="命中策略 ID">
            {{ activeItem.matched_policy_ids.join(", ") || "-" }}
          </n-descriptions-item>
          <n-descriptions-item label="强制注入参数">
            <pre class="mono-code" style="margin: 0">{{ JSON.stringify(activeItem.enforced_params, null, 2) }}</pre>
          </n-descriptions-item>
          <n-descriptions-item label="行级过滤">
            {{ activeItem.rows_before !== null ? `${activeItem.rows_before} → ${activeItem.rows_after}` : "未触发" }}
          </n-descriptions-item>
          <n-descriptions-item label="已裁剪字段">
            {{ activeItem.pruned_fields.join(", ") || "无" }}
          </n-descriptions-item>
          <n-descriptions-item label="已脱敏字段">
            {{ activeItem.transformed_fields.join(", ") || "无" }}
          </n-descriptions-item>
          <n-descriptions-item v-if="activeItem.error_message" label="拒绝 / 错误原因">
            <span style="color: #dc2626">{{ activeItem.error_message }}</span>
          </n-descriptions-item>
        </n-descriptions>
      </n-drawer-content>
    </n-drawer>
  </div>
</template>

<script setup lang="ts">
import { h, onMounted, reactive, ref } from "vue";
import {
  NButton,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NInput,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import type { AuditLogItem, AuditLogPage } from "@/api/types";

const message = useMessage();
const loading = ref(false);
const items = ref<AuditLogItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = 20;

const showDetail = ref(false);
const activeItem = ref<AuditLogItem | null>(null);

const filters = reactive({
  username: "",
  platform_code: "",
  protocol: null as string | null,
  decision: null as string | null,
});

const protocolOptions = [
  { label: "HTTP", value: "http" },
  { label: "MCP", value: "mcp" },
];
const decisionOptions = [
  { label: "放行 (allow)", value: "allow" },
  { label: "拦截 (deny)", value: "deny" },
  { label: "异常 (error)", value: "error" },
];

const columns: DataTableColumns<AuditLogItem> = [
  {
    title: "时间",
    key: "created_at",
    width: 170,
    render: (r) => new Date(r.created_at).toLocaleString(),
  },
  {
    title: "用户 / 应用",
    key: "username",
    render: (r) => (r.app_code ? `${r.username} (via ${r.app_code})` : r.username || "-"),
  },
  {
    title: "协议",
    key: "protocol",
    width: 75,
    render: (r) =>
      h(NTag, { size: "small", type: r.protocol === "mcp" ? "info" : "default", bordered: false }, () =>
        r.protocol.toUpperCase()
      ),
  },
  {
    title: "平台 / 接口",
    key: "platform_code",
    render: (r) => h("code", { class: "mono-code" }, `${r.platform_code}/${r.endpoint_code || "*"}`),
  },
  {
    title: "决策",
    key: "decision",
    width: 85,
    render: (r) => {
      const type = r.decision === "allow" ? "success" : r.decision === "deny" ? "warning" : "error";
      return h(NTag, { size: "small", type, bordered: false }, () => r.decision);
    },
  },
  {
    title: "行过滤",
    key: "rows",
    width: 90,
    render: (r) => (r.rows_before !== null ? `${r.rows_before}→${r.rows_after}` : "-"),
  },
  { title: "耗时", key: "latency_ms", width: 80, render: (r) => `${r.latency_ms}ms` },
  {
    title: "详情",
    key: "detail",
    width: 80,
    render: (r) =>
      h(
        NButton,
        {
          size: "small",
          quaternary: true,
          onClick: () => {
            activeItem.value = r;
            showDetail.value = true;
          },
        },
        () => "查看"
      ),
  },
];

async function loadLogs() {
  loading.value = true;
  try {
    const res = await apiRequest<AuditLogPage>("/api/v1/admin/audit-logs", {
      query: {
        username: filters.username || undefined,
        platform_code: filters.platform_code || undefined,
        protocol: filters.protocol || undefined,
        decision: filters.decision || undefined,
        limit: pageSize,
        offset: (page.value - 1) * pageSize,
      },
    });
    items.value = res.items;
    total.value = res.total;
  } catch (err: any) {
    message.error(err?.detail || "加载审计日志失败");
  } finally {
    loading.value = false;
  }
}

function handleSearch() {
  page.value = 1;
  loadLogs();
}

onMounted(loadLogs);
</script>
