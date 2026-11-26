<template>
  <n-config-provider :theme-overrides="themeOverrides" :locale="zhCN" :date-locale="dateZhCN">
    <n-dialog-provider>
      <n-message-provider>
        <router-view />
      </n-message-provider>
    </n-dialog-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import {
  NConfigProvider,
  NDialogProvider,
  NMessageProvider,
  dateZhCN,
  zhCN,
  type GlobalThemeOverrides,
} from "naive-ui";

const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: "#0f766e",
    primaryColorHover: "#0d9488",
    primaryColorPressed: "#115e59",
    primaryColorSuppl: "#14b8a6",
    borderRadius: "8px",
    fontFamily:
      '"Inter", "PingFang SC", "Noto Sans SC", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  },
  Card: {
    borderRadius: "10px",
  },
};
</script>
