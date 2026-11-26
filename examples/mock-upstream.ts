import { createServer } from "node:http";

const port = Number(process.env.MOCK_PORT ?? 9001);

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
  console.log(
    `[Mock Jira] ${req.method} ${url.pathname}${url.search} | Authorization=${req.headers.authorization ?? "none"}`
  );

  res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
  res.end(
    JSON.stringify({
      total: 1,
      receivedQuery: Object.fromEntries(url.searchParams.entries()),
      internalSecret: "TOP-SECRET-SHOULD-BE-PRUNED",
      issues: [
        {
          key: `${url.searchParams.get("project") ?? "UNKNOWN"}-101`,
          budgetCents: 999999,
          fields: {
            summary: "排查 AI 网关接口权限问题",
            status: { name: "In Progress", internalId: 42 },
            reporter: {
              displayName: "张三",
              emailAddress: "zhangsan@enterprise.com",
              phone: "13812345678",
            },
            description:
              "请联系客户 13987654321 或发邮件至 bob@example.org，身份证 110105199003071234",
          },
        },
      ],
    })
  );
});

server.listen(port, "127.0.0.1", () => {
  console.log(`[Mock Jira] listening on http://127.0.0.1:${port}`);
});
