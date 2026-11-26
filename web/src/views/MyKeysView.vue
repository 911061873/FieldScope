<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">我的 API Key</h1>
        <p class="page-subtitle">
          创建个人 API Key（<code class="mono-code">fs_usr_*</code>）用于 AI Agent / MCP Client 直连数据面，自动生效您绑定的外部数据角色。
        </p>
      </div>
      <n-button type="primary" @click="showCreate = true">创建新 Key</n-button>
    </div>

    <div class="surface-card">
      <n-data-table :columns="columns" :data="keys" :loading="loading" :bordered="false" />
    </div>

    <n-modal v-model:show="showCreate" preset="card" title="创建个人 API Key" style="width: 440px">
      <n-form label-placement="top">
        <n-form-item label="名称" required>
          <n-input v-model:value="newKeyName" placeholder="例如：Claude Desktop MCP" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showCreate = false">取消</n-button>
          <n-button type="primary" :loading="creating" @click="handleCreate">生成 Key</n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal v-model:show="showSecret" preset="card" title="请立即保存您的 API Key" style="width: 520px">
      <n-alert type="warning" :bordered="false" style="margin-bottom: 14px">
        出于安全考虑，明文 Key 仅在此刻展示一次，关闭后无法再次查看。
      </n-alert>
      <div class="secret-box">{{ createdPlainKey }}</div>
      <template #footer>
        <n-space justify="end">
          <n-button @click="copyKey">一键复制</n-button>
          <n-button type="primary" @click="showSecret = false">我已保存</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { h, onMounted, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSpace,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import type { UserApiKey } from "@/api/types";

const message = useMessage();
const loading = ref(false);
const creating = ref(false);
const keys = ref<UserApiKey[]>([]);
const showCreate = ref(false);
const newKeyName = ref("");
const showSecret = ref(false);
const createdPlainKey = ref("");

const columns: DataTableColumns<UserApiKey> = [
  { title: "名称", key: "name" },
  {
    title: "前缀",
    key: "key_prefix",
    render: (row) => h("code", { class: "mono-code" }, `${row.key_prefix}...`),
  },
  {
    title: "状态",
    key: "is_active",
    render: (row) =>
      h(NTag, { type: row.is_active ? "success" : "default", size: "small", bordered: false }, () =>
        row.is_active ? "有效" : "已停用"
      ),
  },
  {
    title: "最近使用",
    key: "last_used_at",
    render: (row) => (row.last_used_at ? new Date(row.last_used_at).toLocaleString() : "未使用"),
  },
  {
    title: "创建时间",
    key: "created_at",
    render: (row) => new Date(row.created_at).toLocaleString(),
  },
  {
    title: "操作",
    key: "actions",
    width: 110,
    render: (row) =>
      h(
        NPopconfirm,
        { onPositiveClick: () => handleRevoke(row.id) },
        {
          trigger: () => h(NButton, { size: "small", type: "error", quaternary: true }, () => "吊销"),
          default: () => `确认吊销 Key「${row.name}」？`,
        }
      ),
  },
];

async function loadKeys() {
  loading.value = true;
  try {
    keys.value = await apiRequest<UserApiKey[]>("/api/v1/admin/auth/me/api-keys");
  } catch (err: any) {
    message.error(err?.detail || "加载失败");
  } finally {
    loading.value = false;
  }
}

async function handleCreate() {
  if (!newKeyName.value.trim()) {
    message.warning("请输入 Key 名称");
    return;
  }
  creating.value = true;
  try {
    const res = await apiRequest<UserApiKey>("/api/v1/admin/auth/me/api-keys", {
      method: "POST",
      body: { name: newKeyName.value.trim() },
    });
    createdPlainKey.value = res.plain_key || "";
    showCreate.value = false;
    newKeyName.value = "";
    showSecret.value = true;
    await loadKeys();
  } catch (err: any) {
    message.error(err?.detail || "创建失败");
  } finally {
    creating.value = false;
  }
}

async function handleRevoke(id: number) {
  try {
    await apiRequest(`/api/v1/admin/auth/me/api-keys/${id}`, { method: "DELETE" });
    message.success("已吊销");
    await loadKeys();
  } catch (err: any) {
    message.error(err?.detail || "吊销失败");
  }
}

async function copyKey() {
  await navigator.clipboard.writeText(createdPlainKey.value);
  message.success("已复制到剪贴板");
}

onMounted(loadKeys);
</script>
