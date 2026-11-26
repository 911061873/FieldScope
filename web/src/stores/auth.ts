import { defineStore } from "pinia";
import { ref, computed } from "vue";
import { apiRequest, getStoredToken, setStoredToken } from "@/api/client";
import type { CurrentUser } from "@/api/types";

export const useAuthStore = defineStore("auth", () => {
  const token = ref<string | null>(getStoredToken());
  const user = ref<CurrentUser | null>(null);
  const loaded = ref(false);

  const isAuthenticated = computed(() => Boolean(token.value));

  function hasPermission(code?: string): boolean {
    if (!code) return true;
    if (!user.value) return false;
    if (user.value.is_superuser) return true;
    return user.value.platform_permissions.includes(code);
  }

  async function login(username: string, password: string): Promise<void> {
    const res = await apiRequest<{ access_token: string }>("/api/v1/admin/auth/login", {
      method: "POST",
      body: { username, password },
      auth: false,
    });
    token.value = res.access_token;
    setStoredToken(res.access_token);
    await fetchMe();
  }

  async function fetchMe(): Promise<CurrentUser | null> {
    if (!token.value) {
      user.value = null;
      loaded.value = true;
      return null;
    }
    try {
      const me = await apiRequest<CurrentUser>("/api/v1/admin/auth/me");
      user.value = me;
      loaded.value = true;
      return me;
    } catch {
      logout();
      return null;
    }
  }

  function logout(): void {
    token.value = null;
    user.value = null;
    loaded.value = true;
    setStoredToken(null);
  }

  return {
    token,
    user,
    loaded,
    isAuthenticated,
    hasPermission,
    login,
    fetchMe,
    logout,
  };
});
