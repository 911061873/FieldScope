<template>
  <div class="schema-editor">
    <div class="editor-header">
      <div>
        <div class="editor-title">接口入参配置</div>
        <div class="editor-hint">
          <template v-if="isMcpTool">
            配置 MCP Tool 入参结构，供 AI 调用时按字段说明传参。
          </template>
          <template v-else>
            按路径参数、查询参数、请求头、请求体分组定义入参，对外暴露为 MCP 工具时自动路由到对应位置。
          </template>
        </div>
      </div>
      <n-radio-group v-model:value="editMode" size="small" @update:value="onModeChange">
        <n-radio-button value="visual">可视化</n-radio-button>
        <n-radio-button value="json">JSON Schema</n-radio-button>
      </n-radio-group>
    </div>

    <!-- Visual Mode -->
    <div v-if="editMode === 'visual'" class="editor-body">
      <!-- 4-tab HTTP param layout -->
      <template v-if="!isMcpTool">
        <n-tabs v-model:value="activeTab" type="segment" size="small" animated>
          <n-tab-pane name="path" :tab="tabLabel('路径参数', countByLoc.path)" />
          <n-tab-pane name="query" :tab="tabLabel('查询参数', countByLoc.query)" />
          <n-tab-pane name="header" :tab="tabLabel('请求头', countByLoc.header)" />
          <n-tab-pane name="body" :tab="tabLabel('请求体', countByLoc.body)" />
        </n-tabs>

        <!-- Contextual helper bar per tab -->
        <div v-if="activeTab === 'path' && missingPathParams.length > 0" class="sync-banner">
          <span>
            路径模板中检测到未添加的参数：
            <code v-for="p in missingPathParams" :key="p" class="mono-chip">{{ p }}</code>
          </span>
          <n-button size="tiny" type="primary" secondary @click="importPathParams">
            一键提取
          </n-button>
        </div>

        <div v-if="activeTab === 'header'" class="subtle-tip">
          平台级认证 Header（如 Authorization / API Key）由「认证与续期」自动注入，此处仅配置接口级动态请求头。
        </div>

        <div
          v-if="activeTab === 'body' && !isBodyMethod"
          class="subtle-tip"
        >
          当前 HTTP 方法为 <b>{{ httpMethod }}</b>，通常使用「查询参数」而非「请求体」。
        </div>
      </template>

      <!-- Action bar for current group -->
      <div class="section-bar">
        <span class="section-label">
          {{ isMcpTool ? `参数列表（${visibleRows.length}）` : `${currentTabTitle}（${visibleRows.length}）` }}
        </span>
        <n-button size="tiny" dashed type="primary" @click="addRow">
          + 添加{{ isMcpTool ? "参数" : currentTabShortName }}
        </n-button>
      </div>

      <div v-if="duplicateNames.length > 0" class="inline-error">
        存在重复参数名（{{ duplicateNames.join("、") }}），同一接口的各分组参数名需保持唯一。
      </div>

      <div v-if="visibleRows.length === 0" class="empty-tip">
        {{ emptyTipText }}
      </div>

      <!-- Compact parameter rows -->
      <div v-for="row in visibleRows" :key="row.uid" class="param-card">
        <div class="param-top-grid">
          <div class="field-col">
            <div class="mini-label">参数名</div>
            <n-input
              v-model:value="row.name"
              size="small"
              class="mono-code"
              :placeholder="namePlaceholder"
              @update:value="emitVisualValue"
            />
          </div>

          <div class="field-col">
            <div class="mini-label">类型</div>
            <n-select
              v-model:value="row.type"
              size="small"
              :options="typeOptionsForLocation(row.location)"
              @update:value="onTypeChange(row)"
            />
          </div>

          <div class="field-col field-req">
            <div class="mini-label">必填</div>
            <div class="req-box">
              <n-checkbox v-model:checked="row.required" @update:checked="emitVisualValue" />
            </div>
          </div>

          <div class="field-col field-actions">
            <n-button size="tiny" quaternary type="error" @click="removeRowByUid(row.uid)">
              删除
            </n-button>
          </div>
        </div>

        <div class="param-desc-row">
          <n-input
            v-model:value="row.description"
            size="small"
            placeholder="参数说明（供 AI 理解用途，如：客户 ID / 每页数量，最大 50）"
            @update:value="emitVisualValue"
          />
        </div>

        <div
          v-if="row.type === 'string' || row.type === 'integer' || row.type === 'number'"
          class="param-enum-row"
        >
          <span class="mini-label" style="white-space: nowrap">可选枚举</span>
          <n-dynamic-tags
            v-model:value="row.enumTags"
            size="small"
            @update:value="onEnumChange(row, $event)"
          />
        </div>
      </div>
    </div>

    <!-- JSON Schema Advanced Mode -->
    <div v-else class="editor-body">
      <n-input
        v-model:value="rawJsonText"
        type="textarea"
        :rows="8"
        class="mono-code"
        placeholder='{"type": "object", "properties": {}, "required": []}'
        @update:value="onRawJsonInput"
      />
      <div v-if="jsonError" class="inline-error">{{ jsonError }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import {
  NButton,
  NCheckbox,
  NDynamicTags,
  NInput,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NTabPane,
  NTabs,
} from "naive-ui";

type ParamLocation = "path" | "query" | "header" | "body";
type JsonSchemaType = "string" | "integer" | "number" | "boolean" | "array" | "object";

interface ParamRow {
  uid: number;
  location: ParamLocation;
  name: string;
  type: JsonSchemaType;
  description: string;
  required: boolean;
  enumTags: string[];
  /** Preserve extra JSON Schema keywords (items, properties, default, minimum, etc.) */
  extra: Record<string, unknown>;
}

const props = withDefaults(
  defineProps<{
    modelValue: Record<string, unknown>;
    pathPattern?: string;
    httpMethod?: string;
    isMcpTool?: boolean;
  }>(),
  {
    pathPattern: "",
    httpMethod: "GET",
    isMcpTool: false,
  }
);

const emit = defineEmits<{
  (e: "update:modelValue", value: Record<string, unknown>): void;
  (e: "validChange", valid: boolean): void;
}>();

const allTypeOptions = [
  { label: "string", value: "string" },
  { label: "integer", value: "integer" },
  { label: "number", value: "number" },
  { label: "boolean", value: "boolean" },
  { label: "array", value: "array" },
  { label: "object", value: "object" },
];

const scalarTypeOptions = allTypeOptions.filter((o) =>
  ["string", "integer", "number", "boolean"].includes(o.value)
);

const queryTypeOptions = allTypeOptions.filter((o) => o.value !== "object");

let nextUid = 1;
const editMode = ref<"visual" | "json">("visual");
const activeTab = ref<ParamLocation>("query");
const rows = ref<ParamRow[]>([]);
const rootExtra = ref<Record<string, unknown>>({});
const rawJsonText = ref("");
const jsonError = ref("");
let internalSync = false;

const isBodyMethod = computed(() =>
  ["POST", "PUT", "PATCH"].includes((props.httpMethod || "GET").toUpperCase())
);

const pathParamNames = computed(() => {
  const names = new Set<string>();
  const pat = props.pathPattern || "";
  const regex = /\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(pat)) !== null) {
    const name = m[1] || m[2];
    if (name) names.add(name);
  }
  return names;
});

const missingPathParams = computed(() => {
  if (props.isMcpTool) return [];
  const existing = new Set(
    rows.value
      .filter((r) => r.location === "path")
      .map((r) => r.name.trim())
      .filter(Boolean)
  );
  return Array.from(pathParamNames.value).filter((name) => !existing.has(name));
});

const countByLoc = computed(() => {
  const counts: Record<ParamLocation, number> = { path: 0, query: 0, header: 0, body: 0 };
  for (const r of rows.value) {
    counts[r.location] += 1;
  }
  return counts;
});

const visibleRows = computed(() => {
  if (props.isMcpTool) return rows.value;
  return rows.value.filter((r) => r.location === activeTab.value);
});

const duplicateNames = computed(() => {
  const seen = new Set<string>();
  const dups = new Set<string>();
  for (const r of rows.value) {
    const name = r.name.trim();
    if (!name) continue;
    if (seen.has(name)) dups.add(name);
    seen.add(name);
  }
  return Array.from(dups);
});

const currentTabTitle = computed(() => {
  const map: Record<ParamLocation, string> = {
    path: "路径参数（替换路径中的 {param}）",
    query: "查询参数（URL ?key=value）",
    header: "请求头（HTTP Headers）",
    body: "请求体字段（JSON Body）",
  };
  return map[activeTab.value];
});

const currentTabShortName = computed(() => {
  const map: Record<ParamLocation, string> = {
    path: "路径参数",
    query: "查询参数",
    header: "请求头",
    body: "Body 字段",
  };
  return map[activeTab.value];
});

const namePlaceholder = computed(() => {
  if (props.isMcpTool) return "例如 dept / keyword";
  const map: Record<ParamLocation, string> = {
    path: "例如 id / key",
    query: "例如 limit / status / keyword",
    header: "例如 X-Locale / X-Tenant-Id",
    body: "例如 title / customer_id",
  };
  return map[activeTab.value];
});

const emptyTipText = computed(() => {
  if (props.isMcpTool) return "暂无参数定义，点击右上角「+ 添加参数」新增。";
  const map: Record<ParamLocation, string> = {
    path: "暂无路径参数。若路径模板含 {id}，可点击上方「一键提取」或手动添加。",
    query: "暂无查询参数，点击右上角「+ 添加查询参数」新增。",
    header: "暂无自定义请求头（平台认证头会自动注入，无需在此添加）。",
    body: "暂无请求体字段，点击右上角「+ 添加 Body 字段」新增。",
  };
  return map[activeTab.value];
});

function tabLabel(title: string, count: number): string {
  return count > 0 ? `${title} (${count})` : title;
}

function typeOptionsForLocation(loc: ParamLocation) {
  if (props.isMcpTool || loc === "body") return allTypeOptions;
  if (loc === "query") return queryTypeOptions;
  return scalarTypeOptions;
}

function normalizeSchemaType(raw: unknown): JsonSchemaType {
  const allowed: JsonSchemaType[] = ["string", "integer", "number", "boolean", "array", "object"];
  if (typeof raw === "string" && allowed.includes(raw as JsonSchemaType)) {
    return raw as JsonSchemaType;
  }
  return "string";
}

function normalizeLocation(raw: unknown, name: string): ParamLocation {
  if (raw === "path" || raw === "query" || raw === "header" || raw === "body") {
    return raw;
  }
  if (pathParamNames.value.has(name)) return "path";
  return isBodyMethod.value ? "body" : "query";
}

function pickInitialTab() {
  if (props.isMcpTool) return;
  if (countByLoc.value.path > 0 || pathParamNames.value.size > 0) {
    activeTab.value = "path";
  } else if (isBodyMethod.value) {
    activeTab.value = "body";
  } else {
    activeTab.value = "query";
  }
}

function syncFromProps(schema: Record<string, unknown>, resetTab = false) {
  const safe = schema && typeof schema === "object" && !Array.isArray(schema) ? schema : {};
  const { type: _t, properties: rawProps, required: rawReq, ...restRoot } = safe;
  rootExtra.value = JSON.parse(JSON.stringify(restRoot));

  const requiredSet = new Set(
    Array.isArray(rawReq) ? rawReq.filter((x): x is string => typeof x === "string") : []
  );
  const propsObj =
    rawProps && typeof rawProps === "object" && !Array.isArray(rawProps)
      ? (rawProps as Record<string, unknown>)
      : {};

  rows.value = Object.entries(propsObj).map(([name, rawDef]) => {
    const def =
      rawDef && typeof rawDef === "object" && !Array.isArray(rawDef)
        ? (rawDef as Record<string, unknown>)
        : {};
    const { type, description, enum: enumVals, "x-in": xIn, ...restProp } = def;
    return {
      uid: nextUid++,
      location: normalizeLocation(xIn, name),
      name,
      type: normalizeSchemaType(type),
      description: typeof description === "string" ? description : "",
      required: requiredSet.has(name),
      enumTags: Array.isArray(enumVals) ? enumVals.map((v) => String(v)) : [],
      extra: JSON.parse(JSON.stringify(restProp)),
    };
  });

  if (resetTab) {
    pickInitialTab();
  }
  rawJsonText.value = JSON.stringify(buildSchemaFromRows(), null, 2);
  jsonError.value = "";
  emit("validChange", true);
}

function parseEnumTag(raw: string, type: JsonSchemaType): { ok: boolean; value: unknown } {
  const trimmed = raw.trim();
  if (type === "integer") {
    const n = Number(trimmed);
    return trimmed !== "" && Number.isInteger(n) ? { ok: true, value: n } : { ok: false, value: null };
  }
  if (type === "number") {
    const n = Number(trimmed);
    return trimmed !== "" && !Number.isNaN(n) ? { ok: true, value: n } : { ok: false, value: null };
  }
  return { ok: true, value: raw };
}

function buildSchemaFromRows(): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  const required: string[] = [];

  for (const row of rows.value) {
    const name = row.name.trim();
    if (!name) continue;
    const propDef: Record<string, unknown> = {
      ...row.extra,
      type: row.type,
    };
    if (!props.isMcpTool) {
      propDef["x-in"] = row.location;
    }
    if (row.description.trim()) {
      propDef.description = row.description.trim();
    }
    if (
      row.enumTags.length > 0 &&
      (row.type === "string" || row.type === "integer" || row.type === "number")
    ) {
      const parsedEnum: unknown[] = [];
      for (const tag of row.enumTags) {
        const p = parseEnumTag(tag, row.type);
        if (p.ok) parsedEnum.push(p.value);
      }
      if (parsedEnum.length > 0) {
        propDef.enum = parsedEnum;
      }
    }
    properties[name] = propDef;
    if (row.required && !required.includes(name)) {
      required.push(name);
    }
  }

  const out: Record<string, unknown> = {
    ...rootExtra.value,
    type: "object",
    properties,
  };
  if (required.length > 0) {
    out.required = required;
  }
  return out;
}

watch(
  () => props.modelValue,
  (val) => {
    if (internalSync) {
      internalSync = false;
      return;
    }
    syncFromProps(val, true);
  },
  { immediate: true, deep: true }
);

function emitValue(val: Record<string, unknown>) {
  internalSync = true;
  emit("update:modelValue", val);
}

function emitVisualValue() {
  const schema = buildSchemaFromRows();
  rawJsonText.value = JSON.stringify(schema, null, 2);
  jsonError.value = "";
  emit("validChange", true);
  emitValue(schema);
}

function addRow() {
  const loc: ParamLocation = props.isMcpTool ? "body" : activeTab.value;
  rows.value.push({
    uid: nextUid++,
    location: loc,
    name: "",
    type: "string",
    description: "",
    required: loc === "path",
    enumTags: [],
    extra: {},
  });
}

function removeRowByUid(uid: number) {
  const idx = rows.value.findIndex((r) => r.uid === uid);
  if (idx !== -1) {
    rows.value.splice(idx, 1);
    emitVisualValue();
  }
}

function importPathParams() {
  for (const name of missingPathParams.value) {
    rows.value.push({
      uid: nextUid++,
      location: "path",
      name,
      type: "string",
      description: `路径参数 ${name}`,
      required: true,
      enumTags: [],
      extra: {},
    });
  }
  emitVisualValue();
}

function onTypeChange(row: ParamRow) {
  if (row.type === "integer" || row.type === "number") {
    row.enumTags = row.enumTags.filter((t) => parseEnumTag(t, row.type).ok);
  }
  emitVisualValue();
}

function onEnumChange(row: ParamRow, tags: string[]) {
  const cleaned = tags.filter((t) => parseEnumTag(t, row.type).ok).map((t) => t.trim());
  row.enumTags = Array.from(new Set(cleaned));
  emitVisualValue();
}

function onModeChange(nextMode: "visual" | "json") {
  if (nextMode === "json") {
    rawJsonText.value = JSON.stringify(buildSchemaFromRows(), null, 2);
    jsonError.value = "";
    emit("validChange", true);
  } else {
    onRawJsonInput(rawJsonText.value);
    if (jsonError.value) {
      editMode.value = "json";
      return;
    }
    syncFromProps(props.modelValue, false);
  }
}

function onRawJsonInput(text: string) {
  try {
    const parsed = JSON.parse(text || "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("必须是 JSON 对象");
    }
    jsonError.value = "";
    emit("validChange", true);
    emitValue(parsed as Record<string, unknown>);
  } catch {
    jsonError.value = "JSON Schema 格式不正确，请检查语法";
    emit("validChange", false);
  }
}
</script>

<style scoped>
.schema-editor {
  width: 100%;
  background: #f8fafc;
  border: 1px solid var(--fs-border);
  border-radius: 8px;
  padding: 12px 14px;
}

.editor-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 10px;
}

.editor-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--fs-text);
}

.editor-hint {
  font-size: 12px;
  color: var(--fs-text-muted);
  margin-top: 2px;
}

.editor-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.sync-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 7px 10px;
  font-size: 12px;
  color: #0f766e;
  background: var(--fs-primary-soft);
  border: 1px solid #99f6e4;
  border-radius: 6px;
}

.mono-chip {
  font-family: "JetBrains Mono", ui-monospace, monospace;
  font-size: 11.5px;
  background: #ffffff;
  border: 1px solid #99f6e4;
  border-radius: 4px;
  padding: 1px 5px;
  margin-left: 4px;
}

.subtle-tip {
  font-size: 12px;
  color: var(--fs-text-muted);
  background: var(--fs-surface);
  border: 1px solid var(--fs-border);
  border-radius: 6px;
  padding: 6px 10px;
}

.section-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.section-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--fs-text-muted);
}

.empty-tip {
  font-size: 12px;
  color: var(--fs-text-muted);
  padding: 12px;
  background: var(--fs-surface);
  border: 1px dashed var(--fs-border);
  border-radius: 6px;
  text-align: center;
}

.param-card {
  background: var(--fs-surface);
  border: 1px solid var(--fs-border);
  border-radius: 6px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.param-top-grid {
  display: grid;
  grid-template-columns: 1fr 112px 44px auto;
  gap: 8px;
  align-items: end;
}

.field-col {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.field-req {
  align-items: center;
}

.req-box {
  height: 28px;
  display: flex;
  align-items: center;
}

.field-actions {
  padding-bottom: 2px;
}

.mini-label {
  font-size: 11.5px;
  color: var(--fs-text-muted);
}

.param-enum-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.inline-error {
  font-size: 12px;
  color: #dc2626;
}
</style>
