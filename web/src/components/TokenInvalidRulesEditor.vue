<template>
  <div class="invalid-rules-editor">
    <div class="editor-header">
      <div>
        <div class="editor-title">Token 失效判定规则</div>
        <div class="editor-hint">
          命中以下任意 HTTP 状态码或响应体条件时，自动刷新 Token 并重放当前请求一次。
        </div>
      </div>
      <n-space :size="6" align="center">
        <n-dropdown
          v-if="editMode === 'visual'"
          trigger="click"
          :options="presetOptions"
          @select="applyPreset"
        >
          <n-button size="tiny" secondary>套用模板</n-button>
        </n-dropdown>
        <n-radio-group v-model:value="editMode" size="small" @update:value="onModeChange">
          <n-radio-button value="visual">可视化</n-radio-button>
          <n-radio-button value="json">JSON</n-radio-button>
        </n-radio-group>
      </n-space>
    </div>

    <!-- Visual Mode -->
    <div v-if="editMode === 'visual'" class="editor-body">
      <div class="section-row">
        <span class="section-label">HTTP 状态码</span>
        <n-select
          :value="httpStatusStrings"
          multiple
          filterable
          tag
          size="small"
          style="flex: 1"
          :options="httpStatusOptions"
          placeholder="默认 401，可输入如 403 回车添加"
          @update:value="onHttpStatusesChange"
        />
      </div>

      <div class="body-rules-block">
        <div class="section-bar">
          <span class="section-label">响应体 JSON 规则（适用于 HTTP 200 返回业务错误码）</span>
          <n-button size="tiny" dashed type="primary" @click="addRow">+ 添加规则</n-button>
        </div>

        <div v-if="rows.length === 0" class="empty-tip">
          暂无响应体规则，当前仅在命中上方 HTTP 状态码时触发自动刷新。
        </div>

        <div v-for="(row, idx) in rows" :key="row.uid" class="rule-card">
          <div class="rule-grid">
            <div class="field-col field-path">
              <div class="mini-label">JSONPath 路径</div>
              <n-input
                v-model:value="row.path"
                size="small"
                class="mono-code"
                placeholder="$.code / $.errcode"
                @update:value="emitVisualValue"
              />
            </div>

            <div class="field-col field-op">
              <div class="mini-label">匹配方式</div>
              <n-select
                v-model:value="row.operator"
                size="small"
                :options="[
                  { label: '等于', value: 'equals' },
                  { label: '属于列表', value: 'in_values' },
                ]"
                @update:value="onOperatorChange(row)"
              />
            </div>

            <div class="field-col field-type">
              <div class="mini-label">值类型</div>
              <n-select
                v-model:value="row.valueType"
                size="small"
                :options="[
                  { label: '数字', value: 'number' },
                  { label: '字符串', value: 'string' },
                  { label: '布尔', value: 'boolean' },
                ]"
                @update:value="onValueTypeChange(row)"
              />
            </div>

            <div class="field-col field-actions">
              <n-button size="tiny" quaternary type="error" @click="removeRow(idx)">删除</n-button>
            </div>
          </div>

          <div class="value-row">
            <div class="mini-label">
              {{ row.operator === "equals" ? "目标值" : "目标值列表（点击 + 添加，回车确认）" }}
            </div>

            <!-- Single value: equals -->
            <template v-if="row.operator === 'equals'">
              <n-input-number
                v-if="row.valueType === 'number'"
                v-model:value="row.equalsNumber"
                size="small"
                style="width: 100%"
                placeholder="例如 40001"
                @update:value="emitVisualValue"
              />
              <n-select
                v-else-if="row.valueType === 'boolean'"
                v-model:value="row.equalsBoolean"
                size="small"
                :options="[
                  { label: 'true', value: 'true' },
                  { label: 'false', value: 'false' },
                ]"
                @update:value="emitVisualValue"
              />
              <n-input
                v-else
                v-model:value="row.equalsString"
                size="small"
                class="mono-code"
                placeholder="例如 TOKEN_EXPIRED"
                @update:value="emitVisualValue"
              />
            </template>

            <!-- Multi values: in_values -->
            <template v-else>
              <n-dynamic-tags
                v-model:value="row.listTags"
                size="small"
                :type="row.valueType === 'number' ? 'info' : 'default'"
                @update:value="onTagsChange(row, $event)"
              />
              <div v-if="row.tagHint" class="inline-error">{{ row.tagHint }}</div>
            </template>
          </div>
        </div>
      </div>
    </div>

    <!-- JSON Advanced Mode -->
    <div v-else class="editor-body">
      <n-input
        v-model:value="rawJsonText"
        type="textarea"
        :rows="5"
        class="mono-code"
        placeholder='{"http_statuses": [401], "body_rules": [{"path": "$.code", "in_values": [40001]}]}'
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
  NDropdown,
  NDynamicTags,
  NInput,
  NInputNumber,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NSpace,
} from "naive-ui";

export interface BodyInvalidRuleItem {
  path: string;
  equals?: unknown;
  in_values?: unknown[];
}

export interface TokenInvalidRulesValue {
  http_statuses: number[];
  body_rules: BodyInvalidRuleItem[];
}

type ValueType = "number" | "string" | "boolean";

interface VisualRuleRow {
  uid: number;
  path: string;
  operator: "equals" | "in_values";
  valueType: ValueType;
  equalsNumber: number | null;
  equalsString: string;
  equalsBoolean: "true" | "false";
  listTags: string[];
  tagHint: string;
}

const props = defineProps<{
  modelValue: TokenInvalidRulesValue;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: TokenInvalidRulesValue): void;
  (e: "validChange", valid: boolean): void;
}>();

let nextUid = 1;
const editMode = ref<"visual" | "json">("visual");
const httpStatuses = ref<number[]>([401]);
const rows = ref<VisualRuleRow[]>([]);
const rawJsonText = ref("");
const jsonError = ref("");
let internalSync = false;

const httpStatusOptions = [
  { label: "401 Unauthorized", value: "401" },
  { label: "403 Forbidden", value: "403" },
  { label: "419 Token Expired", value: "419" },
];

const presetOptions = [
  { label: "企业微信 / 钉钉 ($.errcode ∈ [40014, 42001, 41001])", key: "wecom" },
  { label: "通用数字错误码 ($.code = 401)", key: "code_401" },
  { label: "飞书 tenant_access_token ($.code ∈ [99991663, 99991668])", key: "feishu" },
  { label: "字符串错误码 ($.error.code ∈ [TOKEN_EXPIRED, INVALID_TOKEN])", key: "str_code" },
];

const httpStatusStrings = computed(() => httpStatuses.value.map((n) => String(n)));

function inferValueType(sample: unknown): ValueType {
  if (typeof sample === "number") return "number";
  if (typeof sample === "boolean") return "boolean";
  return "string";
}

function parseValueByType(raw: string, type: ValueType): { ok: boolean; value: unknown } {
  const trimmed = raw.trim();
  if (type === "number") {
    if (!trimmed || Number.isNaN(Number(trimmed))) {
      return { ok: false, value: null };
    }
    return { ok: true, value: Number(trimmed) };
  }
  if (type === "boolean") {
    if (trimmed.toLowerCase() === "true") return { ok: true, value: true };
    if (trimmed.toLowerCase() === "false") return { ok: true, value: false };
    return { ok: false, value: null };
  }
  return { ok: true, value: raw };
}

function ruleToRow(rule: BodyInvalidRuleItem): VisualRuleRow {
  const hasInValues = Array.isArray(rule.in_values) && rule.in_values.length > 0;
  if (hasInValues) {
    const vType = inferValueType(rule.in_values![0]);
    return {
      uid: nextUid++,
      path: rule.path || "",
      operator: "in_values",
      valueType: vType,
      equalsNumber: null,
      equalsString: "",
      equalsBoolean: "true",
      listTags: rule.in_values!.map((v) => String(v)),
      tagHint: "",
    };
  }
  const vType = inferValueType(rule.equals);
  return {
    uid: nextUid++,
    path: rule.path || "",
    operator: "equals",
    valueType: vType,
    equalsNumber: typeof rule.equals === "number" ? rule.equals : null,
    equalsString: rule.equals !== undefined && rule.equals !== null ? String(rule.equals) : "",
    equalsBoolean: rule.equals === false ? "false" : "true",
    listTags: [],
    tagHint: "",
  };
}

function rowsToPayload(): TokenInvalidRulesValue {
  const body_rules: BodyInvalidRuleItem[] = [];
  for (const r of rows.value) {
    const path = r.path.trim();
    if (!path) continue;
    if (r.operator === "equals") {
      if (r.valueType === "number") {
        if (r.equalsNumber !== null && !Number.isNaN(r.equalsNumber)) {
          body_rules.push({ path, equals: r.equalsNumber });
        }
      } else if (r.valueType === "boolean") {
        body_rules.push({ path, equals: r.equalsBoolean === "true" });
      } else if (r.equalsString !== "") {
        body_rules.push({ path, equals: r.equalsString });
      }
    } else {
      const parsedVals: unknown[] = [];
      for (const tag of r.listTags) {
        const p = parseValueByType(tag, r.valueType);
        if (p.ok) parsedVals.push(p.value);
      }
      if (parsedVals.length > 0) {
        body_rules.push({ path, in_values: parsedVals });
      }
    }
  }
  return {
    http_statuses: [...httpStatuses.value],
    body_rules,
  };
}

function syncFromProps(val: TokenInvalidRulesValue) {
  httpStatuses.value = Array.isArray(val?.http_statuses) ? [...val.http_statuses] : [401];
  rows.value = Array.isArray(val?.body_rules) ? val.body_rules.map(ruleToRow) : [];
  rawJsonText.value = JSON.stringify(
    { http_statuses: httpStatuses.value, body_rules: val?.body_rules || [] },
    null,
    2
  );
  jsonError.value = "";
  emit("validChange", true);
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

function emitValue(val: TokenInvalidRulesValue) {
  internalSync = true;
  emit("update:modelValue", val);
}

function emitVisualValue() {
  const payload = rowsToPayload();
  rawJsonText.value = JSON.stringify(payload, null, 2);
  jsonError.value = "";
  emit("validChange", true);
  emitValue(payload);
}

function onHttpStatusesChange(vals: string[]) {
  const parsed = vals
    .map((s) => Number(s))
    .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599);
  httpStatuses.value = Array.from(new Set(parsed));
  emitVisualValue();
}

function addRow() {
  rows.value.push({
    uid: nextUid++,
    path: "$.code",
    operator: "in_values",
    valueType: "number",
    equalsNumber: 40001,
    equalsString: "",
    equalsBoolean: "true",
    listTags: [],
    tagHint: "",
  });
}

function removeRow(index: number) {
  rows.value.splice(index, 1);
  emitVisualValue();
}

function onOperatorChange(row: VisualRuleRow) {
  row.tagHint = "";
  if (row.operator === "in_values" && row.listTags.length === 0) {
    if (row.valueType === "number" && row.equalsNumber !== null) {
      row.listTags = [String(row.equalsNumber)];
    } else if (row.valueType === "string" && row.equalsString) {
      row.listTags = [row.equalsString];
    }
  } else if (row.operator === "equals" && row.listTags.length > 0) {
    const first = row.listTags[0];
    const parsed = parseValueByType(first, row.valueType);
    if (row.valueType === "number" && parsed.ok) row.equalsNumber = parsed.value as number;
    if (row.valueType === "string") row.equalsString = first;
    if (row.valueType === "boolean" && parsed.ok) {
      row.equalsBoolean = parsed.value ? "true" : "false";
    }
  }
  emitVisualValue();
}

function onValueTypeChange(row: VisualRuleRow) {
  row.tagHint = "";
  if (row.operator === "in_values") {
    // Filter out tags incompatible with the newly selected type
    row.listTags = row.listTags.filter((t) => parseValueByType(t, row.valueType).ok);
  }
  emitVisualValue();
}

function onTagsChange(row: VisualRuleRow, tags: string[]) {
  const valid: string[] = [];
  let rejected = "";
  for (const t of tags) {
    if (parseValueByType(t, row.valueType).ok) {
      valid.push(t.trim());
    } else {
      rejected = t;
    }
  }
  row.listTags = Array.from(new Set(valid));
  row.tagHint = rejected
    ? `已忽略「${rejected}」：当前值类型为「${row.valueType === "number" ? "数字" : "布尔"}」`
    : "";
  emitVisualValue();
}

function applyPreset(key: string) {
  const presets: Record<string, BodyInvalidRuleItem> = {
    wecom: { path: "$.errcode", in_values: [40014, 42001, 41001] },
    code_401: { path: "$.code", equals: 401 },
    feishu: { path: "$.code", in_values: [99991663, 99991668] },
    str_code: { path: "$.error.code", in_values: ["TOKEN_EXPIRED", "INVALID_TOKEN"] },
  };
  const item = presets[key];
  if (!item) return;
  rows.value.push(ruleToRow(item));
  emitVisualValue();
}

function onModeChange(nextMode: "visual" | "json") {
  if (nextMode === "json") {
    rawJsonText.value = JSON.stringify(rowsToPayload(), null, 2);
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
    let next: TokenInvalidRulesValue;
    // Also tolerate pasting a bare body_rules array directly
    if (Array.isArray(parsed)) {
      next = { http_statuses: [...httpStatuses.value], body_rules: parsed };
    } else if (parsed && typeof parsed === "object") {
      const statuses = Array.isArray(parsed.http_statuses)
        ? parsed.http_statuses.filter((n: unknown) => typeof n === "number")
        : [401];
      const rules = Array.isArray(parsed.body_rules) ? parsed.body_rules : [];
      next = { http_statuses: statuses, body_rules: rules };
    } else {
      throw new Error("格式必须是对象或数组");
    }
    jsonError.value = "";
    emit("validChange", true);
    emitValue(next);
  } catch {
    jsonError.value = "JSON 格式不正确，请检查语法";
    emit("validChange", false);
  }
}
</script>

<style scoped>
.invalid-rules-editor {
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
  gap: 12px;
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
  gap: 10px;
}

.section-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.section-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}

.section-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--fs-text-muted);
  white-space: nowrap;
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

.rule-card {
  background: var(--fs-surface);
  border: 1px solid var(--fs-border);
  border-radius: 6px;
  padding: 10px 12px;
  margin-bottom: 8px;
}

.rule-card:last-child {
  margin-bottom: 0;
}

.rule-grid {
  display: grid;
  grid-template-columns: 1fr 110px 92px auto;
  gap: 8px;
  align-items: end;
}

.field-col {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.field-actions {
  padding-bottom: 2px;
}

.value-row {
  margin-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.mini-label {
  font-size: 11.5px;
  color: var(--fs-text-muted);
}

.inline-error {
  font-size: 12px;
  color: #dc2626;
  margin-top: 4px;
}
</style>
