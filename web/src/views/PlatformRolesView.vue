<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">平台内部角色</h1>
        <p class="page-subtitle">
          限制用户在 FieldScope 管理后台本身的功能菜单与管理接口权限（与外部数据角色完全隔离）。
        </p>
      </div>
      <n-button v-if="canWrite" type="primary" @click="openCreate">新建平台角色</n-button>
    </div>

    <div class="surface-card">
      <n-data-table :columns="columns" :data="roles" :loading="loading" :bordered="false" />
    </div>

    <n-modal
      v-model:show="showForm"
      preset="card"
      :title="editing ? '编辑平台角色' : '新建平台角色'"
      style="width: 620px"
    >
      <n-form label-placement="top">
        <n-grid :cols="2" :x-gap="14">
          <n-gi>
            <n-form-item label="角色编码" required>
              <n-input v-model:value="form.code" :disabled="Boolean(editing)" placeholder="例如 ops_viewer" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="角色名称" required>
              <n-input v-model:value="form.name" placeholder="例如 运维只读" />
            </n-form-item>
          </n-gi>
        </n-grid>
        <n-form-item label="描述">
          <n-input v-model:value="form.description" placeholder="说明该角色在管理后台的职责范围" />
        </n-form-item>
        <n-form-item label="平台内部权限点">
          <n-checkbox-group
            v-model:value="form.permission_codes"
            :disabled="editing?.code === 'super_admin'"
            style="width: 100%"
          >
            <div v-for="(items, mod) in groupedPermissions" :key="mod" class="perm-group">
              <div class="perm-group-title">{{ moduleLabel(String(mod)) }}</div>
              <n-space wrap :size="[16, 10]">
                <n-checkbox v-for="p in items" :key="p.code" :value="p.code">
                  {{ p.name }}
                  <span class="perm-code">({{ p.code }})</span>
                </n-checkbox>
              </n-space>
            </div>
          </n-checkbox-group>
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showForm = false">取消</n-button>
          <n-button type="primary" :loading="saving" @click="handleSave">保存</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, reactive, ref } from "vue";
import {
  NButton,
  NCheckbox,
  NCheckboxGroup,
  NDataTable,
  NForm,
  NFormItem,
  NGi,
  NGrid,
  NInput,
  NModal,
  NPopconfirm,
  NSpace,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import type { PlatformPermission, PlatformRole } from "@/api/types";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const message = useMessage();
const canWrite = computed(() => auth.hasPermission("platform_role:write"));

const loading = ref(false);
const saving = ref(false);
const roles = ref<PlatformRole[]>([]);
const allPerms = ref<PlatformPermission[]>([]);
const showForm = ref(false);
const editing = ref<PlatformRole | null>(null);

const form = reactive({
  code: "",
  name: "",
  description: "",
  permission_codes: [] as string[],
});

const groupedPermissions = computed(() => {
  const groups: Record<string, PlatformPermission[]> = {};
  for (const p of allPerms.value) {
    if (!groups[p.module]) groups[p.module] = [];
    groups[p.module].push(p);
  }
  return groups;
});

function moduleLabel(mod: string): string {
  const map: Record<string, string> = {
    iam: "身份与平台权限",
    platform: "三方平台接入",
    policy: "外部数据角色与策略",
    audit: "审计日志",
  };
  return map[mod] || mod;
}

const columns = computed<DataTableColumns<PlatformRole>>(() => [
  { title: "编码", key: "code", render: (r) => h("code", { class: "mono-code" }, r.code) },
  {
    title: "角色名称",
    key: "name",
    render: (r) =>
      h(NSpace, { align: "center", size: 6 }, () => [
        h("span", r.name),
        r.is_system
          ? h(NTag, { size: "tiny", bordered: false, type: "info" }, () => "内置")
          : null,
      ]),
  },
  { title: "说明", key: "description", ellipsis: { tooltip: true } },
  {
    title: "权限数",
    key: "permissions",
    width: 100,
    render: (r) => h(NTag, { size: "small", bordered: false }, () => `${r.permissions.length} 项`),
  },
  {
    title: "操作",
    key: "actions",
    width: 150,
    render: (r) =>
      canWrite.value
        ? h(NSpace, { size: 4 }, () => [
            h(NButton, { size: "small", quaternary: true, onClick: () => openEdit(r) }, () => "配置"),
            !r.is_system
              ? h(
                  NPopconfirm,
                  { onPositiveClick: () => handleDelete(r.id) },
                  {
                    trigger: () =>
                      h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                    default: () => `确认删除平台角色「${r.name}」？`,
                  }
                )
              : null,
          ])
        : "-",
  },
]);

async function loadData() {
  loading.value = true;
  try {
    const [rList, pList] = await Promise.all([
      apiRequest<PlatformRole[]>("/api/v1/admin/platform-roles"),
      apiRequest<PlatformPermission[]>("/api/v1/admin/platform-permissions"),
    ]);
    roles.value = rList;
    allPerms.value = pList;
  } catch (err: any) {
    message.error(err?.detail || "加载失败");
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  editing.value = null;
  Object.assign(form, { code: "", name: "", description: "", permission_codes: [] });
  showForm.value = true;
}

function openEdit(row: PlatformRole) {
  editing.value = row;
  Object.assign(form, {
    code: row.code,
    name: row.name,
    description: row.description,
    permission_codes: row.permissions.map((p) => p.code),
  });
  showForm.value = true;
}

async function handleSave() {
  saving.value = true;
  try {
    if (editing.value) {
      const payload: Record<string, unknown> = {
        name: form.name,
        description: form.description,
      };
      if (editing.value.code !== "super_admin") {
        payload.permission_codes = form.permission_codes;
      }
      await apiRequest(`/api/v1/admin/platform-roles/${editing.value.id}`, {
        method: "PATCH",
        body: payload,
      });
    } else {
      await apiRequest("/api/v1/admin/platform-roles", {
        method: "POST",
        body: { ...form },
      });
    }
    message.success("保存成功");
    showForm.value = false;
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "保存失败");
  } finally {
    saving.value = false;
  }
}

async function handleDelete(id: number) {
  try {
    await apiRequest(`/api/v1/admin/platform-roles/${id}`, { method: "DELETE" });
    message.success("已删除");
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

onMounted(loadData);
</script>

<style scoped>
.perm-group {
  border: 1px solid var(--fs-border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 10px;
  background: #fafafa;
}

.perm-group-title {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--fs-text);
  margin-bottom: 8px;
}

.perm-code {
  font-size: 11.5px;
  color: var(--fs-text-muted);
}
</style>
