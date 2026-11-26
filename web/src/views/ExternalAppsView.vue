<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">外部应用管理（代调用模式）</h1>
        <p class="page-subtitle">
          为第三方业务系统签发应用凭证（<code class="mono-code">fs_app_*</code>），调用数据面时通过指定请求头传递实际用户标识。
        </p>
      </div>
      <n-button v-if="canWrite" type="primary" @click="openCreate">新建外部应用</n-button>
    </div>

    <div class="surface-card">
      <n-data-table :columns="columns" :data="apps" :loading="loading" :bordered="false" />
    </div>

    <n-modal v-model:show="showForm" preset="card" :title="editing ? '编辑外部应用' : '新建外部应用'" style="width: 480px">
      <n-form label-placement="top">
        <n-form-item label="应用编码 (app_code)" required>
          <n-input v-model:value="form.app_code" :disabled="Boolean(editing)" placeholder="例如 oa_portal" />
        </n-form-item>
        <n-form-item label="应用名称" required>
          <n-input v-model:value="form.name" placeholder="例如 企业 OA 门户" />
        </n-form-item>
        <n-form-item label="用户标识请求头">
          <n-input v-model:value="form.user_identity_header" placeholder="默认 X-FieldScope-User" />
        </n-form-item>
        <n-form-item label="描述">
          <n-input v-model:value="form.description" type="textarea" :rows="2" />
        </n-form-item>
        <n-form-item label="状态">
          <n-switch v-model:value="form.is_active" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showForm = false">取消</n-button>
          <n-button type="primary" :loading="saving" @click="handleSave">保存</n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal v-model:show="showSecret" preset="card" title="请保存应用 API Key" style="width: 520px">
      <n-alert type="warning" :bordered="false" style="margin-bottom: 14px">
        该明文密钥仅显示一次，请妥善保存至第三方应用配置中。
      </n-alert>
      <div class="secret-box">{{ revealedKey }}</div>
      <template #footer>
        <n-space justify="end">
          <n-button @click="copyKey">复制密钥</n-button>
          <n-button type="primary" @click="showSecret = false">完成</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from "vue";
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
  NSwitch,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import type { ExternalApp } from "@/api/types";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const message = useMessage();
const canWrite = computed(() => auth.hasPermission("external_app:write"));

const loading = ref(false);
const saving = ref(false);
const apps = ref<ExternalApp[]>([]);
const showForm = ref(false);
const editing = ref<ExternalApp | null>(null);
const showSecret = ref(false);
const revealedKey = ref("");

const form = reactive({
  app_code: "",
  name: "",
  description: "",
  user_identity_header: "X-FieldScope-User",
  is_active: true,
});

const columns = computed<DataTableColumns<ExternalApp>>(() => [
  { title: "应用编码", key: "app_code", render: (r) => h("code", { class: "mono-code" }, r.app_code) },
  { title: "名称", key: "name" },
  {
    title: "密钥前缀",
    key: "key_prefix",
    render: (r) => h("code", { class: "mono-code" }, `${r.key_prefix}...`),
  },
  {
    title: "用户标识 Header",
    key: "user_identity_header",
    render: (r) => h("code", { class: "mono-code" }, r.user_identity_header),
  },
  {
    title: "状态",
    key: "is_active",
    render: (r) =>
      h(NTag, { type: r.is_active ? "success" : "default", size: "small", bordered: false }, () =>
        r.is_active ? "启用" : "停用"
      ),
  },
  {
    title: "操作",
    key: "actions",
    width: 240,
    render: (r) =>
      canWrite.value
        ? h(NSpace, { size: 4 }, () => [
            h(NButton, { size: "small", quaternary: true, onClick: () => openEdit(r) }, () => "编辑"),
            h(
              NPopconfirm,
              { onPositiveClick: () => handleRotate(r) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "warning" }, () => "轮换密钥"),
                default: () => "轮换后旧密钥立即失效，确认继续？",
              }
            ),
            h(
              NPopconfirm,
              { onPositiveClick: () => handleDelete(r.id) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                default: () => `确认删除应用「${r.name}」？`,
              }
            ),
          ])
        : "-",
  },
]);

async function loadApps() {
  loading.value = true;
  try {
    apps.value = await apiRequest<ExternalApp[]>("/api/v1/admin/external-apps");
  } catch (err: any) {
    message.error(err?.detail || "加载失败");
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  editing.value = null;
  Object.assign(form, {
    app_code: "",
    name: "",
    description: "",
    user_identity_header: "X-FieldScope-User",
    is_active: true,
  });
  showForm.value = true;
}

function openEdit(row: ExternalApp) {
  editing.value = row;
  Object.assign(form, {
    app_code: row.app_code,
    name: row.name,
    description: row.description,
    user_identity_header: row.user_identity_header,
    is_active: row.is_active,
  });
  showForm.value = true;
}

async function handleSave() {
  saving.value = true;
  try {
    if (editing.value) {
      await apiRequest(`/api/v1/admin/external-apps/${editing.value.id}`, {
        method: "PATCH",
        body: {
          name: form.name,
          description: form.description,
          user_identity_header: form.user_identity_header,
          is_active: form.is_active,
        },
      });
      message.success("已更新");
    } else {
      const created = await apiRequest<ExternalApp>("/api/v1/admin/external-apps", {
        method: "POST",
        body: { ...form },
      });
      revealedKey.value = created.plain_key || "";
      showSecret.value = true;
    }
    showForm.value = false;
    await loadApps();
  } catch (err: any) {
    message.error(err?.detail || "保存失败");
  } finally {
    saving.value = false;
  }
}

async function handleRotate(row: ExternalApp) {
  try {
    const res = await apiRequest<ExternalApp>(`/api/v1/admin/external-apps/${row.id}/rotate-key`, {
      method: "POST",
    });
    revealedKey.value = res.plain_key || "";
    showSecret.value = true;
    await loadApps();
  } catch (err: any) {
    message.error(err?.detail || "轮换失败");
  }
}

async function handleDelete(id: number) {
  try {
    await apiRequest(`/api/v1/admin/external-apps/${id}`, { method: "DELETE" });
    message.success("已删除");
    await loadApps();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

async function copyKey() {
  await navigator.clipboard.writeText(revealedKey.value);
  message.success("已复制");
}

onMounted(loadApps);
</script>
