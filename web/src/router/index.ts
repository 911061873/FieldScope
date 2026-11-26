import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "@/stores/auth";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "login",
      component: () => import("@/views/LoginView.vue"),
      meta: { public: true, title: "登录 — FieldScope" },
    },
    {
      path: "/",
      component: () => import("@/layouts/AdminLayout.vue"),
      children: [
        {
          path: "",
          name: "dashboard",
          component: () => import("@/views/DashboardView.vue"),
          meta: { title: "概览 — FieldScope" },
        },
        {
          path: "platforms",
          name: "platforms",
          component: () => import("@/views/PlatformsView.vue"),
          meta: { permission: "platform:read", title: "三方平台接入 — FieldScope" },
        },
        {
          path: "external-roles",
          name: "external-roles",
          component: () => import("@/views/ExternalRolesView.vue"),
          meta: { permission: "external_role:read", title: "外部数据角色与策略 — FieldScope" },
        },
        {
          path: "users",
          name: "users",
          component: () => import("@/views/UsersView.vue"),
          meta: { permission: "user:read", title: "用户管理 — FieldScope" },
        },
        {
          path: "platform-roles",
          name: "platform-roles",
          component: () => import("@/views/PlatformRolesView.vue"),
          meta: { permission: "platform_role:read", title: "平台内部角色 — FieldScope" },
        },
        {
          path: "external-apps",
          name: "external-apps",
          component: () => import("@/views/ExternalAppsView.vue"),
          meta: { permission: "external_app:read", title: "外部应用管理 — FieldScope" },
        },
        {
          path: "audit-logs",
          name: "audit-logs",
          component: () => import("@/views/AuditLogsView.vue"),
          meta: { permission: "audit:read", title: "审计日志 — FieldScope" },
        },
        {
          path: "my-keys",
          name: "my-keys",
          component: () => import("@/views/MyKeysView.vue"),
          meta: { title: "我的 API Key — FieldScope" },
        },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  if (to.meta.title) {
    document.title = String(to.meta.title);
  }
  if (to.meta.public) {
    if (auth.isAuthenticated && to.name === "login") {
      return { name: "dashboard" };
    }
    return true;
  }

  if (!auth.isAuthenticated) {
    return { name: "login" };
  }

  if (!auth.loaded) {
    await auth.fetchMe();
  }
  if (!auth.user) {
    return { name: "login" };
  }

  const reqPerm = to.meta.permission as string | undefined;
  if (reqPerm && !auth.hasPermission(reqPerm)) {
    return { name: "dashboard" };
  }
  return true;
});

export default router;
