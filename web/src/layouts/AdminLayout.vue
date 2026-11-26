<template>
  <n-layout has-sider style="height: 100vh">
    <n-layout-sider
      bordered
      collapse-mode="width"
      :collapsed-width="64"
      :width="232"
      :collapsed="collapsed"
      show-trigger
      @collapse="collapsed = true"
      @expand="collapsed = false"
      style="background: #ffffff"
    >
      <div class="brand-bar" @click="router.push('/')">
        <div class="brand-mark">FS</div>
        <div v-if="!collapsed" class="brand-text">
          <div class="brand-name">FieldScope</div>
          <div class="brand-sub">细粒度数据连接器</div>
        </div>
      </div>

      <n-menu
        :collapsed="collapsed"
        :collapsed-width="64"
        :collapsed-icon-size="20"
        :options="menuOptions"
        :value="activeKey"
        @update:value="handleMenuSelect"
      />
    </n-layout-sider>

    <n-layout style="background: var(--fs-bg)">
      <n-layout-header bordered class="top-header">
        <div class="header-left">
          <span class="header-section">{{ currentTitle }}</span>
        </div>
        <div class="header-right">
          <n-tag v-if="auth.user?.is_superuser" size="small" type="success" :bordered="false">
            超级管理员
          </n-tag>
          <n-dropdown :options="userMenuOptions" @select="handleUserMenu">
            <n-button quaternary size="small">
              {{ auth.user?.display_name || auth.user?.username }}
            </n-button>
          </n-dropdown>
        </div>
      </n-layout-header>

      <n-layout-content content-style="padding: 22px 26px; max-width: 1440px; margin: 0 auto;">
        <router-view />
      </n-layout-content>
    </n-layout>
  </n-layout>
</template>

<script setup lang="ts">
import { computed, h, ref, type Component } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  NButton,
  NDropdown,
  NIcon,
  NLayout,
  NLayoutContent,
  NLayoutHeader,
  NLayoutSider,
  NMenu,
  NTag,
  type MenuOption,
} from "naive-ui";
import {
  AppsOutline,
  DocumentTextOutline,
  GridOutline,
  KeyOutline,
  LayersOutline,
  PeopleOutline,
  ShieldCheckmarkOutline,
  ServerOutline,
} from "@vicons/ionicons5";
import { useAuthStore } from "@/stores/auth";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const collapsed = ref(false);

function renderIcon(icon: Component) {
  return () => h(NIcon, null, { default: () => h(icon) });
}

interface NavDef {
  key: string;
  label: string;
  icon: Component;
  permission?: string;
}

const allNavItems: NavDef[] = [
  { key: "dashboard", label: "工作台概览", icon: GridOutline },
  { key: "platforms", label: "三方平台接入", icon: ServerOutline, permission: "platform:read" },
  {
    key: "external-roles",
    label: "外部数据角色",
    icon: ShieldCheckmarkOutline,
    permission: "external_role:read",
  },
  { key: "users", label: "用户管理", icon: PeopleOutline, permission: "user:read" },
  {
    key: "platform-roles",
    label: "平台内部角色",
    icon: LayersOutline,
    permission: "platform_role:read",
  },
  {
    key: "external-apps",
    label: "外部应用 (代调)",
    icon: AppsOutline,
    permission: "external_app:read",
  },
  { key: "audit-logs", label: "审计日志", icon: DocumentTextOutline, permission: "audit:read" },
  { key: "my-keys", label: "我的 API Key", icon: KeyOutline },
];

const menuOptions = computed<MenuOption[]>(() =>
  allNavItems
    .filter((item) => auth.hasPermission(item.permission))
    .map((item) => ({
      key: item.key,
      label: item.label,
      icon: renderIcon(item.icon),
    }))
);

const activeKey = computed(() => String(route.name || "dashboard"));

const currentTitle = computed(() => {
  const found = allNavItems.find((i) => i.key === activeKey.value);
  return found ? found.label : "工作台";
});

const userMenuOptions = [
  { label: "我的 API Key", key: "my-keys" },
  { type: "divider", key: "d1" },
  { label: "退出登录", key: "logout" },
];

function handleMenuSelect(key: string) {
  router.push({ name: key });
}

function handleUserMenu(key: string) {
  if (key === "logout") {
    auth.logout();
    router.push({ name: "login" });
  } else if (key === "my-keys") {
    router.push({ name: "my-keys" });
  }
}
</script>

<style scoped>
.brand-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 58px;
  padding: 0 16px;
  border-bottom: 1px solid var(--fs-border);
  cursor: pointer;
}

.brand-mark {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: var(--fs-primary);
  color: #ffffff;
  font-weight: 700;
  font-size: 13px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  letter-spacing: 0.02em;
}

.brand-text {
  overflow: hidden;
  line-height: 1.2;
}

.brand-name {
  font-size: 15px;
  font-weight: 700;
  color: var(--fs-text);
}

.brand-sub {
  font-size: 11px;
  color: var(--fs-text-muted);
}

.top-header {
  height: 58px;
  padding: 0 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #ffffff;
}

.header-section {
  font-size: 15px;
  font-weight: 600;
  color: var(--fs-text);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>
