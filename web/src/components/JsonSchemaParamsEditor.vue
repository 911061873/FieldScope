<template>
  <div class="schema-editor">
    <div class="editor-header">
      <div>
        <div class="editor-title">入参定义（JSON Schema）</div>
        <div class="editor-hint">
          <template v-if="isMcpTool">
            定义 MCP Tool 的入参结构，AI 将按此说明填充调用参数。
          </template>
          <template v-else>
            供 AI / MCP 调用时识别参数；与路径中 <code>{参数}</code> 同名将填入路径，其余自动作为
            {{ isBodyMethod ? "JSON Body" : "Query 参数" }}。
          </template>
        </div>
      </div>
      <n-space :size="6" align="center">
        <n-button
          v-if="editMode === 'visual' && missingPathParams.length > 0"
          size="tiny"
          secondary
          type="primary"
          @click="importPathParams"
        >
          提取路径参数 ({{ missingPathParams.length }})
        </n-button>
        <n-radio-group v-model:value="editMode" size="small" @update:value="onModeChange">
          <n-radio-button value="visual">可视化</n-radio-button>
          <n-radio-button value="json">JSON</n-radio-button>
        </n-radio-group>
      </n-space>
    </div>

    <!-- Visual Mode -->
    <div v-if="editMode === 'visual'" class="editor-body">
      <div class="section-bar">
        <span class="section-label">参数列表（共 {{ rows.length }} 个）</span>
        <n-button size="tiny" dashed type="primary" @click="addRow">+ 添加参数</n-button>
      </div>

      <div v-if="rows.length === 0" class="empty-tip">
        暂无入参定义（仅走 HTTP 代理或无参接口可留空；暴露给 AI / MCP 时建议补充参数说明）。
      </div>

      <div v-for="(row, idx) in rows" :key="row.uid" class="param-card">
        <div class="param-top-grid">
          <div class="field-col">
            <div class="mini-label-row">
              <span class="mini-label">参数名</span>
              <n-tag
                v-if="!isMcpTool && row.name.trim()"
                size="tiny"
                :type="getParamLocation(row.name.trim()) === 'Path' ? 'success' : 'info'"
                :bordered="false"
              >
                {{ getParamLocation(row.name.trim()) }}
              </n-tag>
            </div>
            <n-input
              v-model:value="row.name"
              size="small"
              class="mono-code"
              placeholder="例如 id / limit / status"
              @update:value="emitVisualValue"
            />
          </div>

          <div class="field-col">
            <div class="mini-label">类型</div>
            <n-select
              v-model:value="row.type"
              size="small"
              :options="typeOptions"
              @update:value="onTypeChange(row)"
            />
          </div>

          <div class="field-col field-req">
            <div class="mini-label">必填</div>
            <div style="height: 28px; display: flex; align-items: center">
              <n-checkbox v-model:checked="row.required" @update:checked="emitVisualValue" />
            </div>
          </div>

          <div class="field-col field-actions">
            <n-button size="tiny" quaternary type="error" @click="removeRow(idx)">删除</n-button>
          </div>
        </div>

        <div class="param-desc-row">
          <n-input
            v-model:value="row.description"
            size="small"
            placeholder="参数说明（给 AI 看，例如：客户 ID / 每页条数，最大 50）"
            @update:value="emitVisualValue"
          />
        </div>

        <div
          v-if="row.type === 'string' || row.type === 'integer' || row.type === 'number'"
          class="param-enum-row"
        >
          <span class="mini-label" style="white-space: nowrap">枚举值（可选）</span>
          <n-dynamic-tags
            v-model:value="row.enumTags"
            size="small"
            @update:value="onEnumChange(row, $event)"
          />
        </div>
      </div>
    </div>

    <!-- JSON Advanced Mode -->
    <div v-else class="editor-body">
      <n-input
        v-model:value="rawJsonText"
        type="textarea"
        :rows="7"
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
  NSpace,
  NTag,
} from "naive-ui";

type JsonSchemaType = "string" | "integer" | "number" | "boolean" | "array" | "object";

interface ParamRow {
  uid: number;
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

const typeOptions = [
  { label: "string", value: "string" },
  { label: "integer", value: "integer" },
  { label: "number", value: "number" },
  { label: "boolean", value: "boolean" },
  { label: "array", value: "array" },
  { label: "object", value: "object" },
];

let nextUid = 1;
const editMode = ref<"visual" | "json">("visual");
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
  const existing = new Set(rows.value.map((r) => r.name.trim()).filter(Boolean));
  return Array.from(pathParamNames.value).filter((name) => !existing.has(name));
});

function getParamLocation(name: string): "Path" | "Query" | "Body" {
  if (pathParamNames.value.has(name)) return "Path";
  return isBodyMethod.value ? "Body" : "Query";
}

function normalizeSchemaType(raw: unknown): JsonSchemaType {
  const allowed: JsonSchemaType[] = ["string", "integer", "number", "boolean", "array", "object"];
  if (typeof raw === "string" && allowed.includes(raw as JsonSchemaType)) {
    return raw as JsonSchemaType;
  }
  return "string";
}

function syncFromProps(schema: Record<string, unknown>) {
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
    const { type, description, enum: enumVals, ...restProp } = def;
    return {
      uid: nextUid++,
      name,
      type: normalizeSchemaType(type),
      description: typeof description === "string" ? description : "",
      required: requiredSet.has(name),
      enumTags: Array.isArray(enumVals) ? enumVals.map((v) => String(v)) : [],
      extra: JSON.parse(JSON.stringify(restProp)),
    };
  });

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
    syncFromProps(val);
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
  rows.value.push({
    uid: nextUid++,
    name: "",
    type: "string",
    description: "",
    required: false,
    enumTags: [],
    extra: {},
  });
}

function removeRow(index: number) {
  rows.value.splice(index, 1);
  emitVisualValue();
}

function importPathParams() {
  for (const name of missingPathParams.value) {
    rows.value.push({
      uid: nextUid++,
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
    syncFromProps(props.modelValue);
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
  padding: 10px 12px;
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
  grid-template-columns: 1fr 112px 46px auto;
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

.field-actions {
  padding-bottom: 2px;
}

.mini-label-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
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
  margin-top: 4px;
}
</style>
