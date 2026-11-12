// minimal in memory stand in for cloudflare d1 backed by node sqlite
import { DatabaseSync } from "node:sqlite";

class Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }
  bind(...params) {
    return new Statement(this.db, this.sql, params);
  }
  #args() {
    // d1 lets one value serve a repeated n placeholder node sqlite wants them by name
    if (!/\?\d/.test(this.sql)) return this.params;
    return [Object.fromEntries(this.params.map((value, i) => [`?${i + 1}`, value]))];
  }
  #exec() {
    const stmt = this.db.prepare(this.sql);
    const returnsRows = /^\s*(select|pragma)/i.test(this.sql) || /returning/i.test(this.sql);
    if (returnsRows) return { results: stmt.all(...this.#args()), meta: { changes: 0 } };
    const info = stmt.run(...this.#args());
    return { results: [], meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) } };
  }
  async first() {
    return this.#exec().results[0] ?? null;
  }
  async all() {
    return this.#exec();
  }
  async run() {
    return this.#exec();
  }
}

export function createD1() {
  const db = new DatabaseSync(":memory:");
  return {
    prepare: (sql) => new Statement(db, sql),
    batch: async (statements) => {
      const out = [];
      for (const statement of statements) out.push(await statement.run());
      return out;
    },
    raw: db,
  };
}
