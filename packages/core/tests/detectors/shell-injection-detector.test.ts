import { describe, it, expect } from "vitest";
import type { Finding, ScanContext } from "@talaljaber/vibesafe-shared";
import { ShellInjectionDetector } from "../../src/detectors/shell-injection-detector.js";
import { expectRubric } from "../helpers/rubric.js";

const createContext = (files: Record<string, string>): ScanContext => ({
  rootPath: "/fake",
  projectContext: {} as ScanContext["projectContext"],
  files: Object.keys(files),
  config: { rootPath: "/fake" },
  readFile: async (f) => files[f] ?? "",
});

const run = async (files: Record<string, string>): Promise<Finding[]> => {
  const findings = await new ShellInjectionDetector().detect(createContext(files));
  expectRubric(findings);
  const again = await new ShellInjectionDetector().detect(createContext(files));
  expect(again.map((f) => f.id)).toEqual(findings.map((f) => f.id));
  return findings;
};

const sh = (...lines: string[]): string => ["#!/usr/bin/env bash", ...lines].join("\n") + "\n";
const rule = (fs: Finding[], r: string): Finding[] =>
  fs.filter((f) => f.ruleId === `injection/${r}`);

describe("injection/shell-eval-remote-content", () => {
  it("flags eval and source of downloaded content", async () => {
    const f = rule(
      await run({
        "scripts/a.sh": sh(
          'eval "$(curl -fsSL https://example.com/helpers.sh)"',
          "eval $(wget -qO- https://example.com/env.sh)",
          "source <(curl -s https://example.com/lib.sh)",
          ". <(curl -s https://example.com/lib.sh)",
          'source /dev/stdin <<< "$(curl -s https://example.com/x.sh)"',
        ),
      }),
      "shell-eval-remote-content",
    );
    expect(f.map((x) => x.line)).toEqual([2, 3, 4, 5, 6]);
    for (const x of f) expect([x.severity, x.confidence]).toEqual(["high", "high"]);
  });

  it("flags it inside conditionals", async () => {
    const f = await run({
      "ci/b.sh": sh('if [ -z "$X" ]; then eval "$(curl -s https://e.com/s)"; fi'),
    });
    expect(rule(f, "shell-eval-remote-content")).toHaveLength(1);
  });

  it("stays silent for local eval, pipes, comments, strings and other file kinds", async () => {
    const f = await run({
      "scripts/c.sh": sh(
        'eval "$(ssh-agent -s)"',
        'eval "$(pyenv init -)"',
        "source ./lib.sh",
        "curl -fsSL https://example.com/i.sh | bash",
        'echo "run: eval \\"$(curl https://example.com)\\""',
        '# eval "$(curl -s https://example.com/x)"',
        "curl -fsSL https://example.com/f -o /tmp/f && sha256sum -c sums && source /tmp/f",
      ),
      "src/app.ts": 'eval("$(curl https://example.com)")',
    });
    expect(rule(f, "shell-eval-remote-content")).toEqual([]);
  });
});

describe("injection/shell-sql-interpolation", () => {
  it("flags an unquoted heredoc expanding an argument-derived variable", async () => {
    const f = rule(
      await run({
        "scripts/fix.sh": sh(
          'ORG="${1:?org required}"',
          'CARRIER="$2"',
          'psql "$DATABASE_URL" <<SQL',
          "UPDATE shipments SET status = 'BOOKED'",
          "WHERE carrier = '${CARRIER}' AND org = '$ORG';",
          "SQL",
          "echo done",
        ),
      }),
      "shell-sql-interpolation",
    );
    expect(f).toHaveLength(1);
    expect([f[0]!.line, f[0]!.endLine, f[0]!.severity, f[0]!.confidence]).toEqual([
      6,
      7,
      "high",
      "high",
    ]);
  });

  it("flags -c with direct args, transitive variables and read", async () => {
    const f = rule(
      await run({
        "db/a.sh": sh('psql -U app -c "DELETE FROM users WHERE id = $1"'),
        "db/b.sh": sh('TABLE="$1"', "T2=$TABLE", 'mysql -e "TRUNCATE $T2"'),
        "db/c.sh": sh(
          "read -r NAME",
          'sqlite3 app.db "SELECT 1"',
          "psql -tAc \"SELECT * FROM t WHERE n = '$NAME'\"",
        ),
        "db/d.sh": sh("Q=\"select * from t where a = '$OPTARG'\"", 'psql -c "$Q"'),
        "db/e.sh": sh("<<-EOT", "x", "EOT", "mysql <<-SQL", "\tDROP TABLE ${1};", "\tSQL"),
      }),
      "shell-sql-interpolation",
    );
    expect(f.map((x) => x.file).sort()).toEqual([
      "db/a.sh",
      "db/b.sh",
      "db/c.sh",
      "db/d.sh",
      "db/e.sh",
    ]);
  });

  it("flags a client captured via command substitution, backticks or a bare separator", async () => {
    const f = rule(
      await run({
        "db/a.sh": sh('count=$(psql "$DB" -tAc "SELECT 1 FROM t WHERE a = \'$1\'")'),
        "db/b.sh": sh("n=`psql -tAc \"SELECT 1 FROM t WHERE a = '$1'\"`"),
        "db/c.sh": sh('true;psql -c "DELETE FROM t WHERE id = $1"'),
        "db/d.sh": sh('count="$(psql "$DB" -tAc "SELECT 1 FROM t WHERE a = \'$1\'")"'),
      }),
      "shell-sql-interpolation",
    );
    expect(f.map((x) => x.file).sort()).toEqual(["db/a.sh", "db/b.sh", "db/c.sh", "db/d.sh"]);
  });

  it("does not read the database argument as SQL after a no-argument flag", async () => {
    const f = await run({
      "a.sh": sh('DB="${1:?usage}"; sqlite3 -table "$DB" "SELECT id, email FROM users LIMIT 20"'),
      "b.sh": sh('sqlite3 -line "$1" "SELECT count(*) FROM users"'),
      "c.sh": sh('sqlite3 -quote "$1" "SELECT 1"'),
      "d.sh": sh('sqlite3 -safe "$1" ".tables"'),
      "e.sh": sh(
        'DB_URL="${1:?usage}"; psql -e "$DB_URL" -v ON_ERROR_STOP=1 -f migrations/001.sql',
      ),
      "f.sh": sh('psql -X -e "$1" < migrations/001.sql'),
    });
    expect(rule(f, "shell-sql-interpolation")).toEqual([]);
  });

  it("keeps mysql -e, cqlsh -e and psql -tAc as positives", async () => {
    const f = rule(
      await run({
        "a.sh": sh('mysql -u app -Bse "DELETE FROM t WHERE id = $1"'),
        "b.sh": sh('cqlsh -e "DELETE FROM t WHERE id = $1"'),
        "c.sh": sh('psql -tAc "DELETE FROM t WHERE id = $1"'),
      }),
      "shell-sql-interpolation",
    );
    expect(f.map((x) => x.file).sort()).toEqual(["a.sh", "b.sh", "c.sh"]);
  });

  it("lowers confidence when the whole SQL text is one positional expansion", async () => {
    const f = rule(
      await run({ "a.sh": sh('psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "$1"') }),
      "shell-sql-interpolation",
    );
    expect(f).toHaveLength(1);
    expect(f[0]?.confidence).toBe("medium");
  });

  it("stays silent for a client name that is only quoted text", async () => {
    const f = await run({
      "q.sh": sh('msg="run psql -c SELECT $1 now"', 'echo "$(date) psql -c SELECT $1"'),
    });
    expect(rule(f, "shell-sql-interpolation")).toEqual([]);
  });
  it("spans multi-line -c commands and reports one finding per statement", async () => {
    const f = rule(
      await run({
        "x.sh": sh(
          "ID=$1",
          'psql "$URL" \\',
          '  -c "UPDATE a SET b = 1',
          '  WHERE id = $ID AND x = $ID"',
        ),
      }),
      "shell-sql-interpolation",
    );
    expect(f).toHaveLength(1);
    expect([f[0]!.line, f[0]!.endLine]).toEqual([5, 5]);
  });

  it("stays silent for safe look-alikes", async () => {
    const f = await run({
      "q.sh": sh(
        "psql \"$DATABASE_URL\" <<'SQL'",
        "UPDATE t SET a = $1;",
        "SQL",
        'psql -v org="$1" -c "SELECT * FROM o WHERE slug = :\'org\'"',
        "STAMP=$(date +%F)",
        "psql \"$DATABASE_URL\" -c \"INSERT INTO log VALUES ('$STAMP', '$HOSTNAME', '$DB_SCHEMA')\"",
        "psql \"$DATABASE_URL\" -c 'SELECT $1'",
        '# psql -c "DELETE FROM t WHERE id = $1"',
        'echo "psql -c SELECT $1"',
      ),
      "n.sh": sh(
        "[[ $1 =~ ^[0-9]+$ ]] || exit 1",
        "ID=$1",
        'psql "$DATABASE_URL" -c "DELETE FROM t WHERE id = $ID"',
      ),
      "o.sh": sh('psql "$1" -c "SELECT 1"', 'psql -d "$2" <<SQL', "SELECT now();", "SQL"),
    });
    expect(rule(f, "shell-sql-interpolation")).toEqual([]);
  });

  it("ignores non-shell files", async () => {
    const f = await run({ "src/db.ts": 'psql -c "DELETE FROM t WHERE id = $1"' });
    expect(f).toEqual([]);
  });
});

describe("injection/shell-sql-interpolation review round 1", () => {
  it("ignores flags of later pipeline commands and non-command mentions", async () => {
    const f = rule(
      await run({
        "scripts/a.sh": sh(
          'psql "$DATABASE_URL" -f q.sql | grep -c "$1"',
          'mysql -u root < schema.sql && echo -e "Loaded $1"',
          'docker compose exec mysql bash -c "mysqldump -u root $1 > dump.sql"',
        ),
      }),
      "shell-sql-interpolation",
    );
    expect(f).toEqual([]);
  });

  it("ignores positional parameters of shell functions", async () => {
    const f = rule(
      await run({
        "scripts/a.sh": sh(
          "run_sql() {",
          '  psql "$DATABASE_URL" -c "$1"',
          "}",
          'run_sql "SELECT 1"',
        ),
      }),
      "shell-sql-interpolation",
    );
    expect(f).toEqual([]);
  });

  it("still flags script arguments in a command after a separator", async () => {
    const f = rule(
      await run({
        "scripts/a.sh": sh('cd /tmp && sudo psql "$DB" -c "DELETE FROM t WHERE id = $1"'),
      }),
      "shell-sql-interpolation",
    );
    expect(f).toHaveLength(1);
  });
});
