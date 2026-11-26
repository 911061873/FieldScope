<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">外部数据角色与四层策略</h1>
        <p class="page-subtitle">
          配置外部系统与 AI 调用权限：三方平台 → 接口/MCP 工具 → 数据范围（参数校验/强制注入 + 行级过滤）→ 字段裁剪与脱敏。
        </p>
      </div>
      <n-button v-if="canWrite" type="primary" @click="openCreateRole">新建外部角色</n-button>
    </div>

    <div class="surface-card">
      <n-data-table :columns="roleColumns" :data="roles" :loading="loading" :bordered="false" />
    </div>

    <!-- Create / Edit External Role Modal -->
    <n-modal
      v-model:show="showRoleModal"
      preset="card"
      :title="editingRole ? '编辑外部数据角色' : '新建外部数据角色'"
      style="width: 460px"
    >
      <n-form label-placement="top">
        <n-form-item label="角色编码" required>
          <n-input v-model:value="roleForm.code" :disabled="Boolean(editingRole)" placeholder="例如 sales_east" />
        </n-form-item>
        <n-form-item label="角色名称" required>
          <n-input v-model:value="roleForm.name" placeholder="例如 华东销售数据角色" />
        </n-form-item>
        <n-form-item label="说明">
          <n-input v-model:value="roleForm.description" type="textarea" :rows="2" />
        </n-form-item>
        <n-form-item label="状态" label-placement="left">
          <n-switch v-model:value="roleForm.is_active" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showRoleModal = false">取消</n-button>
          <n-button type="primary" :loading="savingRole" @click="handleSaveRole">保存</n-button>
        </n-space>
      </template>
    </n-modal>

    <!-- Policies Drawer for Selected External Role -->
    <n-drawer v-model:show="showPoliciesDrawer" :width="820">
      <n-drawer-content :title="`四层策略列表：${activeRole?.name || ''}`">
        <n-space justify="space-between" style="margin-bottom: 14px">
          <n-button v-if="canWrite" type="primary" @click="openCreatePolicy">新增访问策略</n-button>
          <n-tag size="small" :bordered="false">共 {{ activeRole?.policies.length || 0 }} 条策略</n-tag>
        </n-space>
        <n-data-table
          :columns="policyColumns"
          :data="activeRole?.policies || []"
          size="small"
          :bordered="false"
        />
      </n-drawer-content>
    </n-drawer>

    <!-- 4-Layer Policy Editor Modal -->
    <n-modal
      v-model:show="showPolicyModal"
      preset="card"
      :title="editingPolicy ? '编辑四层策略' : '新增四层策略'"
      style="width: 720px"
    >
      <n-form label-placement="top" size="small">
        <n-grid :cols="3" :x-gap="12">
          <n-gi :span="2">
            <n-form-item label="策略名称">
              <n-input v-model:value="policyForm.name" placeholder="例如 华东客户只读且脱敏手机号" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="优先级 (越大越优先)">
              <n-input-number v-model:value="policyForm.priority" :min="0" :max="10000" style="width: 100%" />
            </n-form-item>
          </n-gi>
        </n-grid>

        <n-grid :cols="3" :x-gap="12">
          <n-gi>
            <n-form-item label="① 三方平台" required>
              <n-select
                v-model:value="policyForm.platform_id"
                :options="platformOptions"
                placeholder="选择平台"
                @update:value="policyForm.endpoint_id = null"
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="② 接口 / MCP 工具（留空=平台通配）">
              <n-select
                v-model:value="policyForm.endpoint_id"
                clearable
                :options="endpointOptionsForSelectedPlatform"
                placeholder="全部接口 (通配)"
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="效果 (Effect)">
              <n-select
                v-model:value="policyForm.effect"
                :options="[
                  { label: '允许 (allow)', value: 'allow' },
                  { label: '显式拒绝 (deny)', value: 'deny' },
                ]"
              />
            </n-form-item>
          </n-gi>
        </n-grid>

        <n-divider style="margin: 8px 0 12px">③ 数据范围管控（请求前约束 + 响应后行过滤）</n-divider>
        <n-grid :cols="2" :x-gap="12">
          <n-gi>
            <n-form-item label="请求前校验规则 JSON (validate)">
              <n-input
                v-model:value="policyForm.validateJson"
                type="textarea"
                :rows="3"
                class="mono-code"
                placeholder='[{"expr": "query.limit == null || query.limit <= 50", "message": "最多 50 条"}]'
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="强制参数注入 JSON (enforce)">
              <n-input
                v-model:value="policyForm.enforceJson"
                type="textarea"
                :rows="3"
                class="mono-code"
                placeholder='{"query.region": "{{ user.attributes.region }}"}'
              />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="响应后行级过滤 — 列表路径 (list_path)">
              <n-input v-model:value="policyForm.rowListPath" placeholder="例如 data.items（顶层数组留空）" />
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item label="响应后行级过滤 — 判定表达式 (expr)">
              <n-input
                v-model:value="policyForm.rowExpr"
                class="mono-code"
                placeholder="例如 row.owner == user.username"
              />
            </n-form-item>
          </n-gi>
        </n-grid>

        <n-divider style="margin: 8px 0 12px">④ 字段级权限（裁剪 + 脱敏）</n-divider>
        <n-grid :cols="3" :x-gap="12">
          <n-gi>
            <n-form-item label="字段管控模式">
              <n-select
                v-model:value="policyForm.fieldMode"
                :options="[
                  { label: '不限制字段', value: 'none' },
                  { label: '白名单 (仅返回指定字段)', value: 'allowlist' },
                  { label: '黑名单 (隐藏指定字段)', value: 'denylist' },
                ]"
              />
            </n-form-item>
          </n-gi>
          <n-gi :span="2">
            <n-form-item label="字段路径列表（每行一个，如 data.items[*].phone）">
              <n-input
                v-model:value="policyForm.fieldsText"
                type="textarea"
                :rows="3"
                :disabled="policyForm.fieldMode === 'none'"
                class="mono-code"
                placeholder="data.items[*].id&#10;data.items[*].name&#10;data.items[*].phone"
              />
            </n-form-item>
          </n-gi>
        </n-grid>
        <n-form-item label="字段脱敏变换 JSON（action: mask_phone / mask_email / mask_middle / redact / hash）">
          <n-input
            v-model:value="policyForm.transformsJson"
            type="textarea"
            :rows="2"
            :disabled="policyForm.fieldMode === 'none'"
            class="mono-code"
            placeholder='[{"path": "data.items[*].phone", "action": "mask_phone"}]'
          />
        </n-form-item>
      </n-form>

      <template #footer>
        <n-space justify="end">
          <n-button @click="showPolicyModal = false">取消</n-button>
          <n-button type="primary" :loading="savingPolicy" @click="handleSavePolicy">保存策略</n-button>
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
  NDivider,
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
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import { apiRequest } from "@/api/client";
import type { ExternalPolicy, ExternalRole, PlatformItem } from "@/api/types";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const message = useMessage();
const canWrite = computed(() => auth.hasPermission("external_role:write"));

const loading = ref(false);
const roles = ref<ExternalRole[]>([]);
const platforms = ref<PlatformItem[]>([]);

const showRoleModal = ref(false);
const savingRole = ref(false);
const editingRole = ref<ExternalRole | null>(null);
const roleForm = reactive({ code: "", name: "", description: "", is_active: true });

const showPoliciesDrawer = ref(false);
const activeRole = ref<ExternalRole | null>(null);

const showPolicyModal = ref(false);
const savingPolicy = ref(false);
const editingPolicy = ref<ExternalPolicy | null>(null);
const policyForm = reactive({
  name: "",
  platform_id: null as number | null,
  endpoint_id: null as number | null,
  effect: "allow" as "allow" | "deny",
  priority: 100,
  validateJson: "[]",
  enforceJson: "{}",
  rowListPath: "",
  rowExpr: "",
  fieldMode: "allowlist" as "none" | "allowlist" | "denylist",
  fieldsText: "",
  transformsJson: "[]",
});

const platformMap = computed(() => {
  const m = new Map<number, PlatformItem>();
  for (const p of platforms.value) m.set(p.id, p);
  return m;
});

const platformOptions = computed(() =>
  platforms.value.map((p) => ({ label: `${p.name} (${p.code})`, value: p.id }))
);

const endpointOptionsForSelectedPlatform = computed(() => {
  if (!policyForm.platform_id) return [];
  const plat = platformMap.value.get(policyForm.platform_id);
  if (!plat) return [];
  return plat.endpoints.map((ep) => ({
    label:
      ep.resource_type === "mcp_tool"
        ? `[MCP] ${ep.code}`
        : `[${ep.method || "GET"}] ${ep.code} (${ep.path_pattern || ""})`,
    value: ep.id,
  }));
});

const roleColumns = computed<DataTableColumns<ExternalRole>>(() => [
  { title: "角色编码", key: "code", render: (r) => h("code", { class: "mono-code" }, r.code) },
  { title: "角色名称", key: "name" },
  { title: "说明", key: "description", ellipsis: { tooltip: true } },
  {
    title: "策略数",
    key: "policies",
    width: 90,
    render: (r) => h(NTag, { size: "small", bordered: false }, () => `${r.policies.length} 条`),
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
      h(NSpace, { size: 4 }, () => [
        h(
          NButton,
          { size: "small", quaternary: true, type: "primary", onClick: () => openPolicies(r) },
          () => "配置策略"
        ),
        canWrite.value
          ? h(NButton, { size: "small", quaternary: true, onClick: () => openEditRole(r) }, () => "编辑")
          : null,
        canWrite.value
          ? h(
              NPopconfirm,
              { onPositiveClick: () => handleDeleteRole(r.id) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                default: () => `确认删除外部角色「${r.name}」？`,
              }
            )
          : null,
      ]),
  },
]);

const policyColumns = computed<DataTableColumns<ExternalPolicy>>(() => [
  { title: "名称", key: "name", render: (r) => r.name || `策略 #${r.id}` },
  {
    title: "平台 / 接口",
    key: "platform_id",
    render: (r) => {
      const plat = platformMap.value.get(r.platform_id);
      const ep = plat?.endpoints.find((e) => e.id === r.endpoint_id);
      return h("code", { class: "mono-code" }, `${plat?.code || r.platform_id} / ${ep?.code || "*"}`);
    },
  },
  {
    title: "效果",
    key: "effect",
    width: 80,
    render: (r) =>
      h(NTag, { size: "small", type: r.effect === "allow" ? "success" : "error", bordered: false }, () =>
        r.effect
      ),
  },
  { title: "优先级", key: "priority", width: 75 },
  {
    title: "字段策略",
    key: "field_rules",
    width: 120,
    render: (r) =>
      r.field_rules
        ? `${r.field_rules.mode} (${r.field_rules.fields?.length || 0})`
        : "不限制",
  },
  {
    title: "操作",
    key: "actions",
    width: 130,
    render: (r) =>
      canWrite.value
        ? h(NSpace, { size: 4 }, () => [
            h(NButton, { size: "small", quaternary: true, onClick: () => openEditPolicy(r) }, () => "编辑"),
            h(
              NPopconfirm,
              { onPositiveClick: () => handleDeletePolicy(r.id) },
              {
                trigger: () =>
                  h(NButton, { size: "small", quaternary: true, type: "error" }, () => "删除"),
                default: () => "确认删除此策略？",
              }
            ),
          ])
        : "-",
  },
]);

async function loadData() {
  loading.value = true;
  try {
    const [rList, pList] = await Promise.all([
      apiRequest<ExternalRole[]>("/api/v1/admin/external-roles"),
      auth.hasPermission("platform:read")
        ? apiRequest<PlatformItem[]>("/api/v1/admin/platforms")
        : Promise.resolve([]),
    ]);
    roles.value = rList;
    platforms.value = pList;
    if (activeRole.value) {
      const updated = roles.value.find((r) => r.id === activeRole.value?.id);
      if (updated) activeRole.value = updated;
    }
  } catch (err: any) {
    message.error(err?.detail || "加载失败");
  } finally {
    loading.value = false;
  }
}

function openCreateRole() {
  editingRole.value = null;
  Object.assign(roleForm, { code: "", name: "", description: "", is_active: true });
  showRoleModal.value = true;
}

function openEditRole(row: ExternalRole) {
  editingRole.value = row;
  Object.assign(roleForm, {
    code: row.code,
    name: row.name,
    description: row.description,
    is_active: row.is_active,
  });
  showRoleModal.value = true;
}

async function handleSaveRole() {
  savingRole.value = true;
  try {
    if (editingRole.value) {
      await apiRequest(`/api/v1/admin/external-roles/${editingRole.value.id}`, {
        method: "PATCH",
        body: { name: roleForm.name, description: roleForm.description, is_active: roleForm.is_active },
      });
    } else {
      await apiRequest("/api/v1/admin/external-roles", { method: "POST", body: { ...roleForm } });
    }
    message.success("外部角色已保存");
    showRoleModal.value = false;
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "保存失败");
  } finally {
    savingRole.value = false;
  }
}

async function handleDeleteRole(id: number) {
  try {
    await apiRequest(`/api/v1/admin/external-roles/${id}`, { method: "DELETE" });
    message.success("已删除");
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

function openPolicies(row: ExternalRole) {
  activeRole.value = row;
  showPoliciesDrawer.value = true;
}

function openCreatePolicy() {
  editingPolicy.value = null;
  Object.assign(policyForm, {
    name: "",
    platform_id: platforms.value[0]?.id ?? null,
    endpoint_id: null,
    effect: "allow",
    priority: 100,
    validateJson: "[]",
    enforceJson: "{}",
    rowListPath: "",
    rowExpr: "",
    fieldMode: "allowlist",
    fieldsText: "",
    transformsJson: "[]",
  });
  showPolicyModal.value = true;
}

function openEditPolicy(pol: ExternalPolicy) {
  editingPolicy.value = pol;
  Object.assign(policyForm, {
    name: pol.name,
    platform_id: pol.platform_id,
    endpoint_id: pol.endpoint_id,
    effect: pol.effect,
    priority: pol.priority,
    validateJson: JSON.stringify(pol.request_rules?.validate || [], null, 2),
    enforceJson: JSON.stringify(pol.request_rules?.enforce || {}, null, 2),
    rowListPath: pol.row_filter?.list_path || "",
    rowExpr: pol.row_filter?.expr || "",
    fieldMode: pol.field_rules ? pol.field_rules.mode : "none",
    fieldsText: (pol.field_rules?.fields || []).join("\n"),
    transformsJson: JSON.stringify(pol.field_rules?.transforms || [], null, 2),
  });
  showPolicyModal.value = true;
}

async function handleSavePolicy() {
  if (!activeRole.value || !policyForm.platform_id) {
    message.warning("请选择三方平台");
    return;
  }

  let validateArr: unknown[] = [];
  let enforceObj: Record<string, unknown> = {};
  let transformsArr: unknown[] = [];
  try {
    validateArr = JSON.parse(policyForm.validateJson || "[]");
    enforceObj = JSON.parse(policyForm.enforceJson || "{}");
    transformsArr = JSON.parse(policyForm.transformsJson || "[]");
  } catch {
    message.error("JSON 规则格式不正确");
    return;
  }

  const rowFilter = policyForm.rowExpr.trim()
    ? { list_path: policyForm.rowListPath.trim(), expr: policyForm.rowExpr.trim() }
    : null;

  const fieldRules =
    policyForm.fieldMode === "none"
      ? null
      : {
          mode: policyForm.fieldMode,
          fields: policyForm.fieldsText
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
          transforms: transformsArr,
        };

  const payload = {
    platform_id: policyForm.platform_id,
    endpoint_id: policyForm.endpoint_id,
    name: policyForm.name,
    effect: policyForm.effect,
    priority: policyForm.priority,
    request_rules: { validate: validateArr, enforce: enforceObj },
    row_filter: rowFilter,
    field_rules: fieldRules,
    is_active: true,
  };

  savingPolicy.value = true;
  try {
    if (editingPolicy.value) {
      await apiRequest(`/api/v1/admin/external-policies/${editingPolicy.value.id}`, {
        method: "PATCH",
        body: payload,
      });
    } else {
      await apiRequest(`/api/v1/admin/external-roles/${activeRole.value.id}/policies`, {
        method: "POST",
        body: payload,
      });
    }
    message.success("策略已保存");
    showPolicyModal.value = false;
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "保存策略失败");
  } finally {
    savingPolicy.value = false;
  }
}

async function handleDeletePolicy(policyId: number) {
  try {
    await apiRequest(`/api/v1/admin/external-policies/${policyId}`, { method: "DELETE" });
    message.success("策略已删除");
    await loadData();
  } catch (err: any) {
    message.error(err?.detail || "删除失败");
  }
}

onMounted(loadData);
</script>
