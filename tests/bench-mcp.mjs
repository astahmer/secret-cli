#!/usr/bin/env node
// Benchmark: per-operation CLI subprocess vs one long-lived `secret mcp` server.
// Real vault data (aliases from `secret list --json`), no value printed.
import { spawn, execFile } from 'node:child_process'
import { promisify } from 'node:util'

const run = promisify(execFile)
const WORKERS = (process.env.BENCH_WORKERS ?? '1,2,4,8').split(',').map(Number)
const ROUNDS = Number(process.env.BENCH_ROUNDS ?? '2')

const pct = (values, p) => {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] ?? 0
}
const summary = (label, values) =>
  `${label.padEnd(44)} n=${String(values.length).padStart(3)}  p50=${pct(values, 50).toFixed(1)}ms  p95=${pct(values, 95).toFixed(1)}ms  total=${values.reduce((a, b) => a + b, 0).toFixed(0)}ms`

const resolveAliases = async () => {
  if (process.env.BENCH_ALIASES) return process.env.BENCH_ALIASES.split(',').filter(Boolean)
  const { stdout } = await run('secret', ['list', '--json'])
  const rows = JSON.parse(stdout)
  return rows.slice(0, Number(process.env.BENCH_ALIAS_COUNT ?? '4')).map(r => r.alias)
}
const time = async (fn) => {
  const start = performance.now()
  await fn()
  return performance.now() - start
}

const startMcp = async () => {
  const spawnStart = performance.now()
  const child = spawn('secret', ['mcp'], { stdio: ['pipe', 'pipe', 'inherit'] })
  let buffer = ''
  const pending = new Map()
  let nextId = 1
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', chunk => {
    buffer += chunk
    let index
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).trim()
      buffer = buffer.slice(index + 1)
      if (!line) continue
      const message = JSON.parse(line)
      const waiter = pending.get(message.id)
      if (waiter) {
        pending.delete(message.id)
        waiter(message)
      }
    }
  })
  const request = (method, params) =>
    new Promise((resolve, reject) => {
      const id = nextId++
      const timer = setTimeout(() => {
        pending.delete(id)
        reject(new Error(`timeout: ${method}`))
      }, 30_000)
      pending.set(id, message => {
        clearTimeout(timer)
        resolve(message)
      })
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
    })
  await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'bench', version: '0' } })
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`)
  const coldStart = performance.now() - spawnStart
  const call = async (name, args) => {
    const response = await request('tools/call', { name, arguments: args })
    const result = response.result ?? {}
    const text = result.content?.[0]?.text ?? '{}'
    return { ...JSON.parse(text), isError: result.isError === true }
  }
  const close = () => new Promise(resolve => {
    child.once('exit', resolve)
    child.stdin.end()
  })
  return { call, close, coldStart }
}

const cli = {
  check: alias => run('secret', ['get', alias], { maxBuffer: 1 << 20 }).then(() => ({ valueRead: true })),
  list: () => run('secret', ['list', '--json'], { maxBuffer: 1 << 20 }).then(() => ({})),
  run: alias =>
    run('secret', ['run', '--', process.execPath, '-e', 'process.exit(process.env.' + alias + ' ? 0 : 1)'], {
      maxBuffer: 1 << 20,
      cwd: process.env.BENCH_CWD,
    }),
}

const mcpOps = {
  check: (mcp, alias) => mcp.call('secret_check', { alias }),
  list: mcp => mcp.call('secret_list', {}),
  run: (mcp, alias, cwd) =>
    mcp.call('secret_run', {
      command: [process.execPath, '-e', 'process.exit(process.env.' + alias + ' ? 0 : 1)'],
      cwd,
    }),
}

const withBudget = (promise, ms, label) =>
  Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`op timeout ${ms}ms: ${label}`)), ms)),
  ])

const bench = async (workers, op, { kind, label, budget = 20_000 }) => {
  const durations = []
  let valueReads = 0
  const worker = async () => {
    for (let i = 0; i < ROUNDS; i++) for (const alias of aliases) {
      const started = performance.now()
      const result = await withBudget(op(alias), budget, label)
      durations.push(performance.now() - started)
      if (kind === 'cli' && (result?.valueRead === true)) valueReads += 1
    }
  }
  await Promise.all(Array.from({ length: workers }, worker))
  return { label: `${label} · ${workers} thread${workers === 1 ? '' : 's'}`, durations, valueReads }
}

const aliases = await resolveAliases()
const cwd = process.env.BENCH_CWD ?? process.cwd()
console.log(`aliases: ${aliases.join(', ')} · rounds=${ROUNDS} · ops/worker=${aliases.length * ROUNDS}`)
const trace = (message) => process.env.BENCH_TRACE ? console.log(`  · ${message}`) : undefined

const mcp = await startMcp()
console.log(`mcp server cold start (spawn + initialize): ${mcp.coldStart.toFixed(1)}ms\n`)

const results = []
for (const workers of WORKERS) {
  trace(`start workers=${workers}`)
  results.push(await bench(workers, alias => cli.check(alias), { kind: 'cli', label: 'ref check: CLI get (reads value)' }))
  trace('done check cli')
  results.push(await bench(workers, alias => mcpOps.check(mcp, alias), { kind: 'mcp', label: 'ref check: MCP secret_check' }))
  trace('done check mcp')
  if (!process.env.BENCH_SKIP_LIST) results.push(await bench(workers, () => cli.list(), { kind: 'cli', label: 'list aliases: CLI list --json' }))
  trace('done list cli')
  if (!process.env.BENCH_SKIP_LIST) results.push(await bench(workers, () => mcpOps.list(mcp), { kind: 'mcp', label: 'list aliases: MCP secret_list' }))
  trace('done list mcp')
  results.push(await bench(workers, alias => cli.run(alias), { kind: 'cli', label: 'run cmd: CLI secret run' }))
  trace('done run cli')
  results.push(await bench(workers, alias => mcpOps.run(mcp, alias, cwd), { kind: 'mcp', label: 'run cmd: MCP secret_run' }))
  trace('done run mcp')
}
await mcp.close()

console.log('')
for (const result of results) console.log(summary(result.label, result.durations) + `  valueReads=${result.valueReads}`)
