import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface MigrationFile {
  id: string;
  filename: string;
  sql: string;
}

export class MigrationRunner {
  private migrationsDir: string;

  constructor(migrationsDir?: string) {
    this.migrationsDir = migrationsDir || __dirname;
  }

  getMigrationFiles(): MigrationFile[] {
    const files = fs
      .readdirSync(this.migrationsDir)
      .filter((f) => f.endsWith(".sql"))
      .sort();

    return files.map((filename) => ({
      id: filename.replace(/\.sql$/, ""),
      filename,
      sql: fs.readFileSync(path.join(this.migrationsDir, filename), "utf8"),
    }));
  }

  /**
   * Applies all pending SQL migrations to a database executor function.
   */
  async runMigrations(executeSql: (sql: string) => Promise<void> | void): Promise<string[]> {
    const migrations = this.getMigrationFiles();
    const applied: string[] = [];

    for (const m of migrations) {
      // Split statements on semicolon if necessary or execute whole block
      await executeSql(m.sql);
      applied.push(m.id);
    }

    return applied;
  }
}

export const migrationRunner = new MigrationRunner();
