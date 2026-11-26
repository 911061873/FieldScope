<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">用户管理</h1>
        <p class="page-subtitle">
          维护平台账号与用户属性（供数据范围策略如 <code class="mono-code">&#123;&#123; user.attributes.dept_id &#125;&#125;</code> 引用），并独立分配平台内部角色与外部数据角色。
        </p>
      </div>
      <n-button v-if="canWrite" type="primary" @click="openCreate">新建用户</n-button>
    </div>

    <div class="surface-card">
      <n-data-table :columns="columns" :data="users" :loading="loading" :bordered="false" />
    </div>

    <!-- Create/Edit User Modal -->
    <n-modal
      v-model:show="showForm"
      preset="card"
      :title="editing ? `编辑用户：${editing.username}` : '新建用户'"
      style="width: 560px"
    >
      <n-form label-placement="top">
        <n-grid :cols="2" :x-gap="14">
          <n-gi>
            <n-form-item label="用户名" required>
              <n-input v-model:value="form.username" :disabled="Boolean(editing)" placeholder="例如 alice" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item :label="editing ? '重置密码（留空不修改）' : '初始密码'" :required="!editing">
              <n-input v-model:value="form.password" type="password" show-password-on="click" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="显示名称">
              <n-input v-model:value="form.display_name" placeholder="例如 张三" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="部门">
              <n-input v-model:value="form.department" placeholder="例如 华东销售部" />
            </n-form-item>
          </n-gi>
        </n-grid>
        <n-form-item label="邮箱">
          <n-input v-model:value="form.email" placeholder="alice@company.com" />
        </n-form-item>
        <n-form-item label="扩展属性 JSON（用于数据范围模板变量）">
          <n-input
            v-model:value="form.attributesJson"
            type="textarea"
            :rows="3"
            class="mono-code"
            placeholder='{"dept_id": "D01", "region": "east"}'
          />
        </n-form-item>
        <n-space :size="24">
          <n-form-item label="启用状态" label-placement="left">
            <n-switch v-model:value="form.is_active" />
          </n-form-item>
          <n-form-item label="超级管理员" label-placement="left">
            <n-switch v-model:value="form.is_superuser" />
          </n-form-item>
        </n-space>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showForm = false">取消</n-button>
          <n-button type="primary" :loading="saving" @click="handleSaveUser">保存</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- Dual-Track Role Assignment Modal -->
    <n-modal
      v-model:show="showRolesModal"
      preset="card"
      :title="`双轨角色分配：${roleTarget?.username || ''}`"
      style="width: 560px"
    >
      <n-form label-placement="top">
        <n-form-item label="① 平台内部角色（决定管理后台操作权限）">
          <n-select
            v-model:value="selectedPlatformRoleIds"
            multiple
            :options="platformRoleOptions"
            placeholder="选择平台内部角色"
          />
        </n-form-item>
        <n-form-item label="② 外部数据角色（决定可访问的三方平台 / 接口 / 数据范围 / 字段）">
          <n-select
            v-model:value="selectedExternalRoleIds"
            multiple
            :options="externalRoleOptions"
            placeholder="选择外部数据角色（支持多选，按并集安全合并）"
          />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showRolesModal = false">取消</n-button>
          <n-button type="primary" :loading="savingRoles" @click="handleSaveRoles">保存角色分配</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- Admin User API Keys Drawer -->
    <n-drawer v-model:show="showKeysDrawer" :width="560">
      <n-drawer-content :title="`用户 API Key 管理：${keyTarget?.username || ''}`">
        <n-space style="margin-bottom: 14px">
          <n-input v-model:value="adminNewKeyName" placeholder="输入 Key 名称" style="width: 260px" />
          <n-button type="primary" @click="handleCreateUserKey">签发个人 Key</n-button>
        </n-space>
        <div v-if="adminCreatedKey" style="margin-bottom: 14px">
          <n-alert type="warning" title="请立即复制保存（仅显示一次）" :bordered="false">
            <div class="secret-box" style="margin-top: 8px">{{ adminCreatedKey }}</div>
          </n-alert>
        </div>
        <n-data-table :columns="keyColumns" :data="targetUserKeys" size="small" :bordered="false" />
      </n-drawer-content>
    </n-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from "vue";
import {
  NAlert,
  NButton,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NGi,
  NGrid,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import type { ExternalRole, PlatformRole, UserApiKey, UserItem } from "@/api/types";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const message = useMessage();
const canWrite = computed(() => auth.hasPermission("user:write"));

const loading = ref(false);
const saving = ref(false);
const savingRoles = ref(false);
const users = ref<UserItem[]>([]);
const platformRoles = ref<PlatformRole[]>([]);
const externalRoles = ref<ExternalRole[]>([]);

const showForm = ref(false);
const editing = ref<UserItem | null>(null);
const form = reactive({
  username: "",
  password: "",
  display_name: "",
  email: "",
  department: "",
  attributesJson: "{}",
  is_active: true,
  is_superuser: false,
});

const showRolesModal = ref(false);
const roleTarget = ref<UserItem | null>(null);
const selectedPlatformRoleIds = ref<number[]>([]);
const selectedExternalRoleIds = ref<number[]>([]);

const showKeysDrawer = ref(false);
const keyTarget = ref<UserItem | null>(null);
const targetUserKeys = ref<UserApiKey[]>([]);
const adminNewKeyName = ref("");
const adminCreatedKey = ref("");

const platformRoleOptions = computed(() =>
  platformRoles.value.map((r) => ({ label: `${r.name} (${r.code})`, value: r.id }))
);
const externalRoleOptions = computed(() =>
  externalRoles.value.map((r) => ({ label: `${r.name} (${r.code})`, value: r.id }))
);

const columns = computed<DataTableColumns<UserItem>>(() => [
  {
    title: "用户",
    key: "username",
    render: (r) =>
      h("div", [
        h("div", { style: "font-weight: 600" }, r.username),
        h("div", { style: "font-size: 12px; color: var(--fs-text-muted)" }, r.display_name || "-"),
      ]),
  },
  { title: "部门", key: "department", render: (r) => r.department || "-" },
  {
    title: "平台内部角色",
    key: "platform_roles",
    render: (r) =>
      r.platform_roles.length
        ? h(NSpace, { size: 4, wrap: true }, () =>
            r.platform_roles.map((pr) =>
              h(NTag, { size: "small", type: "info", bordered: false }, () => pr.name)
            )
          )
        : h("span", { style: "color: #94a3b8" }, "无"),
  },
  {
    title: "外部数据角色",
    key: "external_roles",
    render: (r) =>
      r.external_roles.length
        ? h(NSpace, { size: 4, wrap: true }, () =>
            r.external_roles.map((er) =>
              h(NTag, { size: "small", type: "success", bordered: false }, () => er.name)
            )
          )
        : h("span", { style: "color: #94a3b8" }, "无"),
  },
  {
    title: "状态",
    key: "is_active",
    width: 80,
    render: (r) =>
      h(NTag, { size: "small", type: r.is_active ? "success" : "default", bordered: false }, () =>
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
              NButton,
              { size: "small", quaternary: true, type: "primary", onClick: () => openRoles(r) },
              () => "分配角色"
            ),
            h(NButton, { size: "small", quaternary: true, onClick: () => openKeys(r) }, () => "Key"),
            h(
              NPopconfirm,
              { onPositiveClick: () => handleDelete(r.id) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                default: () => `确认删除用户「${r.username}」？`,
              }
            ),
          ])
        : "-",
  },
]);

const keyColumns: DataTableColumns<UserApiKey> = [
  { title: "名称", key: "name" },
  {
    title: "前缀",
    key: "key_prefix",
    render: (r) => h("code", { class: "mono-code" }, `${r.key_prefix}...`),
  },
  {
    title: "操作",
    key: "actions",
    width: 80,
    render: (r) =>
      h(
        NButton,
        { size: "small", quaternary: true, type: "error", onClick: () => handleRevokeUserKey(r.id) },
        () => "吊销"
      ),
  },
];

async function loadData() {
  loading.value = true;
  try {
    users.value = await apiRequest<UserItem[]>("/api/v1/admin/users");
    const extras: Promise<void>[] = [];
    if (auth.hasPermission("platform_role:read")) {
      extras.push(
        apiRequest<PlatformRole[]>("/api/v1/admin/platform-roles").then((res) => {
          platformRoles.value = res;
        })
      );
    }
    if (auth.hasPermission("external_role:read")) {
      extras.push(
        apiRequest<ExternalRole[]>("/api/v1/admin/external-roles").then((res) => {
          externalRoles.value = res;
        })
      );
    }
    await Promise.allSettled(extras);
  } catch (err: any) {
    message.error(err?.detail || "加载失败");
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  editing.value = null;
  Object.assign(form, {
    username: "",
    password: "",
    display_name: "",
    email: "",
    department: "",
    attributesJson: "{}",
    is_active: true,
    is_superuser: false,
  });
  showForm.value = true;
}

function openEdit(row: UserItem) {
  editing.value = row;
  Object.assign(form, {
    username: row.username,
    password: "",
    display_name: row.display_name,
    email: row.email || "",
    department: row.department || "",
    attributesJson: JSON.stringify(row.attributes || {}, null, 2),
    is_active: row.is_active,
    is_superuser: row.is_superuser,
  });
  showForm.value = true;
}

async function handleSaveUser() {
  let parsedAttrs: Record<string, unknown> = {};
  try {
    parsedAttrs = JSON.parse(form.attributesJson || "{}");
  } catch {
    message.error("扩展属性必须是合法 JSON 对象");
    return;
  }

  saving.value = true;
  try {
    if (editing.value) {
      const body: Record<string, unknown> = {
        display_name: form.display_name,
        email: form.email || null,
        department: form.department || null,
        attributes: parsedAttrs,
        is_active: form.is_active,
        is_superuser: form.is_superuser,
      };
      if (form.password) body.password = form.password;
      await apiRequest(`/api/v1/admin/users/${editing.value.id}`, { method: "PATCH", body });
    } else {
      await apiRequest("/api/v1/admin/users", {
        method: "POST",
        body: {
          username: form.username,
          password: form.password,
          display_name: form.display_name,
          email: form.email || null,
          department: form.department || null,
          attributes: parsedAttrs,
          is_active: form.is_active,
          is_superuser: form.is_superuser,
        },
      });
    }
    message.success("已保存");
    showForm.value = false;
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "保存失败");
  } finally {
    saving.value = false;
  }
}

function openRoles(row: UserItem) {
  roleTarget.value = row;
  selectedPlatformRoleIds.value = row.platform_roles.map((r) => r.id);
  selectedExternalRoleIds.value = row.external_roles.map((r) => r.id);
  showRolesModal.value = true;
}

async function handleSaveRoles() {
  if (!roleTarget.value) return;
  savingRoles.value = true;
  try {
    await Promise.all([
      apiRequest(`/api/v1/admin/users/${roleTarget.value.id}/platform-roles`, {
        method: "PUT",
        body: { role_ids: selectedPlatformRoleIds.value },
      }),
      apiRequest(`/api/v1/admin/users/${roleTarget.value.id}/external-roles`, {
        method: "PUT",
        body: { role_ids: selectedExternalRoleIds.value },
      }),
    ]);
    message.success("角色分配已更新");
    showRolesModal.value = false;
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "分配失败");
  } finally {
    savingRoles.value = false;
  }
}

async function openKeys(row: UserItem) {
  keyTarget.value = row;
  adminCreatedKey.value = "";
  adminNewKeyName.value = "";
  showKeysDrawer.value = true;
  targetUserKeys.value = await apiRequest<UserApiKey[]>(`/api/v1/admin/users/${row.id}/api-keys`);
}

async function handleCreateUserKey() {
  if (!keyTarget.value || !adminNewKeyName.value.trim()) {
    message.warning("请输入 Key 名称");
    return;
  }
  const created = await apiRequest<UserApiKey>(
    `/api/v1/admin/users/${keyTarget.value.id}/api-keys`,
    { method: "POST", body: { name: adminNewKeyName.value.trim() } }
  );
  adminCreatedKey.value = created.plain_key || "";
  adminNewKeyName.value = "";
  targetUserKeys.value = await apiRequest<UserApiKey[]>(
    `/api/v1/admin/users/${keyTarget.value.id}/api-keys`
  );
}

async function handleRevokeUserKey(keyId: number) {
  if (!keyTarget.value) return;
  await apiRequest(`/api/v1/admin/users/${keyTarget.value.id}/api-keys/${keyId}`, {
    method: "DELETE",
  });
  message.success("已吊销");
  targetUserKeys.value = await apiRequest<UserApiKey[]>(
    `/api/v1/admin/users/${keyTarget.value.id}/api-keys`
  );
}

async function handleDelete(id: number) {
  try {
    await apiRequest(`/api/v1/admin/users/${id}`, { method: "DELETE" });
    message.success("已删除");
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

onMounted(loadData);
</script>
