import type { AutoFixer } from "@vibeguard/shared";

export class AutoFixRegistry {
  private fixers: Map<string, AutoFixer> = new Map();

  /**
   * Registers a new fixer.
   */
  public register(fixer: AutoFixer): void {
    if (this.fixers.has(fixer.ruleId)) {
      throw new Error(`AutoFixer for rule ${fixer.ruleId} is already registered.`);
    }
    this.fixers.set(fixer.ruleId, fixer);
  }

  /**
   * Retrieves a registered fixer by its rule ID.
   */
  public getFixer(ruleId: string): AutoFixer | undefined {
    return this.fixers.get(ruleId);
  }

  /**
   * Returns all registered fixers.
   */
  public getAllFixers(): AutoFixer[] {
    return Array.from(this.fixers.values());
  }
}

import { GitignoreEnvFixer } from "./gitignore-env-fixer.js";
import { EnvExampleFixer } from "./env-example-fixer.js";
import { ConsoleLogFixer } from "./console-log-fixer.js";

/**
 * Creates and returns a registry populated with the default set of fixers.
 */
export function createDefaultFixRegistry(): AutoFixRegistry {
  const registry = new AutoFixRegistry();
  registry.register(new GitignoreEnvFixer());
  registry.register(new EnvExampleFixer());
  registry.register(new ConsoleLogFixer());
  return registry;
}
