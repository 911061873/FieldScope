export {
  evaluatePolicies,
  type PolicyEvaluationInput,
  type PolicyEvaluationResult,
} from "./engine.ts";
export { evaluateExpression, resolvePath } from "./expr.ts";
export { matchMethod, matchPath, matchPrincipal } from "./matcher.ts";
export { resolveTemplateValue, setNestedValue } from "./template.ts";
