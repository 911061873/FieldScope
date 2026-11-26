export {
  evaluatePolicies,
  isToolVisible,
  type PolicyEvaluationInput,
  type PolicyEvaluationResult,
} from "./engine.ts";
export { evaluateExpression, resolvePath } from "./expr.ts";
export {
  matchMethod,
  matchPath,
  matchPrincipal,
  matchToolName,
} from "./matcher.ts";
export { resolveTemplateValue, setNestedValue } from "./template.ts";
