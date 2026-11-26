<template>
  <main class="login-page">
    <section class="login-shell">
      <div class="login-aside">
        <div class="aside-brand">
          <span class="aside-mark">FS</span>
          <span class="aside-title">FieldScope</span>
        </div>
        <h1 class="aside-heading">企业级细粒度数据连接器平台</h1>
        <p class="aside-desc">
          统一接入第三方 API 与远端 MCP 服务，通过双轨角色体系实现用户级数据范围隔离、动态 Token
          自动续期与字段级裁剪脱敏。
        </p>
        <ul class="aside-points">
          <li>平台内部角色与外部数据角色彻底解耦</li>
          <li>支持静态授权、标准 OAuth2 与自定义 HTTP Token 续期</li>
          <li>同一套策略同时治理 HTTP 代理与 AI MCP 调用</li>
        </ul>
      </div>

      <div class="login-card">
        <h2 class="card-title">登录管理控制台</h2>
        <p class="card-sub">请输入您的平台账号与密码</p>

        <n-form ref="formRef" :model="form" :rules="rules" label-placement="top" size="large">
          <n-form-item label="用户名" path="username">
            <n-input
              id="login-username"
              v-model:value="form.username"
              placeholder="例如 admin"
              @keyup.enter="handleSubmit"
            />
          </n-form-item>
          <n-form-item label="密码" path="password">
            <n-input
              id="login-password"
              v-model:value="form.password"
              type="password"
              show-password-on="click"
              placeholder="请输入密码"
              @keyup.enter="handleSubmit"
            />
          </n-form-item>
          <n-button
            id="login-submit"
            type="primary"
            block
            size="large"
            :loading="loading"
            @click="handleSubmit"
          >
            登录
          </n-button>
        </n-form>

        <div class="dev-hint">
          默认初始化管理员：<code class="mono-code">admin</code> /
          <code class="mono-code">admin123456</code>（生产环境请通过环境变量修改）
        </div>
      </div>
    </section>
  </main>
</template>

<script setup lang="ts">
import { reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { NButton, NForm, NFormItem, NInput, useMessage, type FormInst } from "naive-ui";
import { useAuthStore } from "@/stores/auth";

const router = useRouter();
const auth = useAuthStore();
const message = useMessage();
const formRef = ref<FormInst | null>(null);
const loading = ref(false);

const form = reactive({
  username: "admin",
  password: "",
});

const rules = {
  username: { required: true, message: "请输入用户名", trigger: "blur" },
  password: { required: true, message: "请输入密码", trigger: "blur" },
};

async function handleSubmit() {
  try {
    await formRef.value?.validate();
  } catch {
    return;
  }
  loading.value = true;
  try {
    await auth.login(form.username.trim(), form.password);
    message.success("登录成功");
    router.push({ name: "dashboard" });
  } catch (err: any) {
    message.error(err?.detail || err?.message || "登录失败");
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: #f1f5f9;
}

.login-shell {
  width: 100%;
  max-width: 920px;
  display: grid;
  grid-template-columns: 1.05fr 1fr;
  background: #ffffff;
  border: 1px solid var(--fs-border);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 18px 44px rgba(15, 23, 42, 0.06);
}

.login-aside {
  background: #0f292e;
  color: #e2e8f0;
  padding: 44px 38px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.aside-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 24px;
}

.aside-mark {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  background: #14b8a6;
  color: #042f2e;
  font-weight: 800;
  font-size: 13px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.aside-title {
  font-size: 18px;
  font-weight: 700;
  color: #ffffff;
}

.aside-heading {
  margin: 0 0 12px;
  font-size: 24px;
  line-height: 1.35;
  font-weight: 600;
  color: #ffffff;
}

.aside-desc {
  margin: 0 0 24px;
  font-size: 14px;
  line-height: 1.65;
  color: #cbd5e1;
}

.aside-points {
  margin: 0;
  padding-left: 18px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  font-size: 13.5px;
  color: #99f6e4;
}

.login-card {
  padding: 44px 40px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.card-title {
  margin: 0;
  font-size: 21px;
  font-weight: 600;
  color: var(--fs-text);
}

.card-sub {
  margin: 6px 0 24px;
  font-size: 13.5px;
  color: var(--fs-text-muted);
}

.dev-hint {
  margin-top: 20px;
  padding: 10px 12px;
  border-radius: 8px;
  background: #f8fafc;
  border: 1px solid var(--fs-border);
  font-size: 12px;
  color: var(--fs-text-muted);
}

@media (max-width: 780px) {
  .login-shell {
    grid-template-columns: 1fr;
  }
  .login-aside {
    padding: 28px 24px;
  }
  .login-card {
    padding: 28px 24px;
  }
}
</style>
