/**
 * Unified SQLite storage adapter for Cloudflare Durable Objects and Node.js testing.
 *
 * Supports:
 * - Cloudflare Workers Durable Object SQLite API (`ctx.storage.sql`)
 * - Node.js 22/24 built-in `node:sqlite` (`DatabaseSync`)
 */

export class SqlAdapter {
  /**
   * @param {any} backend Either Cloudflare's `ctx.storage.sql` or `node:sqlite` `DatabaseSync`
   */
  constructor(backend) {
    if (!backend) {
      throw new Error("SqlAdapter requires a non-null database backend.");
    }
    this.backend = backend;
    // Detect whether backend is node:sqlite DatabaseSync (has .prepare) or Cloudflare DO SQL (only has .exec)
    this.isNodeSqlite = typeof backend.prepare === "function";
  }

  /**
   * Execute raw multi-statement SQL string (e.g. schema migration).
   *
   * @param {string} sql
   */
  exec(sql) {
    if (this.isNodeSqlite) {
      this.backend.exec(sql);
    } else {
      // Cloudflare DO sql.exec executes SQL strings directly
      this.backend.exec(sql);
    }
  }

  /**
   * Execute a query expecting rows (SELECT).
   *
   * @param {string} sql
   * @param  {...any} params
   * @returns {Array<Record<string, any>>}
   */
  query(sql, ...params) {
    if (this.isNodeSqlite) {
      const stmt = this.backend.prepare(sql);
      return stmt.all(...params);
    } else {
      const cursor = this.backend.exec(sql, ...params);
      return Array.from(cursor);
    }
  }

  /**
   * Execute a mutating statement (INSERT, UPDATE, DELETE).
   *
   * @param {string} sql
   * @param  {...any} params
   * @returns {{ changes: number, lastInsertRowid?: number | bigint }}
   */
  execute(sql, ...params) {
    if (this.isNodeSqlite) {
      const stmt = this.backend.prepare(sql);
      const res = stmt.run(...params);
      return {
        changes: res.changes,
        lastInsertRowid: res.lastInsertRowid,
      };
    } else {
      const cursor = this.backend.exec(sql, ...params);
      return {
        changes: cursor.rowsWritten ?? 0,
      };
    }
  }

  /**
   * Execute operations within a transaction.
   *
   * @template T
   * @param {() => T} fn
   * @returns {T}
   */
  transaction(fn) {
    this.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.exec("ROLLBACK");
      } catch {
        // Ignore rollback error if already rolled back
      }
      throw err;
    }
  }
}
