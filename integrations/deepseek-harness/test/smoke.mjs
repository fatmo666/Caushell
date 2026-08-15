import { chmodSync, cpSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { apply } from '../caushell-dsh-bash.mjs'

const root = mkdtempSync(join(tmpdir(), 'caushell-dsh-plugin-'))
const adapter = join(root, 'fake-adapter.sh')
const sourceAdapter = fileURLToPath(new URL('fake-adapter.sh', import.meta.url))
cpSync(sourceAdapter, adapter)
chmodSync(adapter, 0o755)

function createContext(initialServices = {}) {
  const listeners = new Map()
  const services = new Map(Object.entries(initialServices))
  let guard
  const cleanups = []
  return {
    ctx: {
      logger: { debug() {} },
      provide(name, value) {
        if (services.has(name)) throw new Error(`duplicate service ${name}`)
        services.set(name, value)
        return () => services.delete(name)
      },
      get(name) {
        return services.get(name)
      },
      tools: {
        guard(value) {
          guard = value
          return () => {}
        },
      },
      on(event, listener) {
        listeners.set(event, listener)
        return () => listeners.delete(event)
      },
      effect(factory) {
        cleanups.push(factory())
      },
    },
    pre: () => listeners.get('tools/pre-execute'),
    guard: (exec) => guard?.(exec),
    service: (name) => services.get(name),
    cleanup: () => cleanups.splice(0).forEach(cleanup => cleanup?.()),
  }
}

const baseExec = (command) => ({
  name: 'bash',
  arguments: { command, description: 'Run test command' },
  callId: `call-${command}`,
  signal: new AbortController().signal,
  agent: { id: 'session-1', session: { header: { cwd: root, id: 'session-1' } } },
})
const next = async () => ({ kind: 'allow' })

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-basic') })
  const pre = harness.pre()
  assert.ok(pre)
  assert.deepEqual(harness.service('caushellDshBash'), { mode: 'ordinary-bash' })

  const allow = await pre(baseExec('allow-command'), next)
  assert.deepEqual(allow, { kind: 'allow' })

  const denyExec = baseExec('deny-command')
  const deny = await pre(denyExec, next)
  assert.deepEqual(deny, { kind: 'deny', reason: '[Caushell] test deny' })
  assert.equal(harness.guard(denyExec), '[Caushell] test deny')

  const ask = await pre(baseExec('ask-command'), next)
  assert.deepEqual(ask, { kind: 'ask', reason: '[Caushell] test ask' })

  const other = await pre({ ...baseExec('deny-command'), name: 'read' }, next)
  assert.deepEqual(other, { kind: 'allow' })

  const persistentExec = { ...baseExec('allow-command'), arguments: { command: 'allow-command' } }
  const persistent = await pre(persistentExec, next)
  assert.match(persistent.reason, /supports ordinary DSH Bash only/)
  assert.equal(persistent.kind, 'deny')
  assert.match(harness.guard(persistentExec), /supports ordinary DSH Bash only/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-composition') })
  const pre = harness.pre()
  assert.ok(pre)

  const downstreamDeny = await pre(baseExec('ask-command'), async () => ({
    kind: 'deny',
    reason: 'downstream denied',
  }))
  assert.deepEqual(downstreamDeny, { kind: 'deny', reason: 'downstream denied' })

  const combinedAsk = await pre(baseExec('ask-command'), async () => ({
    kind: 'ask',
    reason: 'downstream asks too',
  }))
  assert.deepEqual(combinedAsk, {
    kind: 'ask',
    reason: '[Caushell] test ask\ndownstream asks too',
  })

  const denyExec = baseExec('deny-command')
  const denyWithoutApproval = await pre(denyExec, async () => ({
    kind: 'ask',
    reason: 'downstream asks',
  }))
  assert.deepEqual(denyWithoutApproval, { kind: 'deny', reason: '[Caushell] test deny' })
  assert.equal(harness.guard(denyExec), '[Caushell] test deny')
  harness.cleanup()
}

{
  const harness = createContext({
    sandboxPolicy: {
      resolve() {
        return { workspaceRoot: '/policy' }
      },
    },
  })
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-policy-root') })
  const exec = baseExec('policy-root-command')
  exec.arguments.workdir = 'sub'
  assert.deepEqual(await harness.pre()(exec, next), { kind: 'allow' })
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-timeout'), timeoutMs: 20 })
  const pre = harness.pre()
  assert.ok(pre)

  const timeout = await pre(baseExec('delay-command'), next)
  assert.equal(timeout.kind, 'ask')
  assert.match(timeout.reason, /timed out after 20ms/)

  // The timed-out sequential adapter generation is terminated. The next
  // action starts a new generation rather than queuing behind stale work.
  const allow = await pre(baseExec('allow-after-timeout'), next)
  assert.deepEqual(allow, { kind: 'allow' })
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-crash') })
  const pre = harness.pre()
  assert.ok(pre)

  const crash = await pre(baseExec('crash-command'), next)
  assert.equal(crash.kind, 'ask')
  assert.match(crash.reason, /adapter-dsh exited before responding|exited before responding/i)

  // A closed adapter is restarted for the next DSH action.
  const allow = await pre(baseExec('allow-after-crash'), next)
  assert.deepEqual(allow, { kind: 'allow' })
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-invalid') })
  const pre = harness.pre()
  assert.ok(pre)

  const invalid = await pre(baseExec('invalid-command'), next)
  assert.equal(invalid.kind, 'ask')
  assert.match(invalid.reason, /invalid caushell-adapter-dsh response/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-invalid-shape') })
  const pre = harness.pre()
  assert.ok(pre)

  const invalid = await pre(baseExec('invalid-shape-command'), next)
  assert.equal(invalid.kind, 'ask')
  assert.match(invalid.reason, /invalid caushell-adapter-dsh response: unknown decision/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-extra-field') })
  const pre = harness.pre()
  assert.ok(pre)

  const invalid = await pre(baseExec('extra-field-command'), next)
  assert.equal(invalid.kind, 'ask')
  assert.match(invalid.reason, /unknown response field/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: '/does/not/exist', storeRoot: join(root, 'store-fallback') })
  const pre = harness.pre()
  assert.ok(pre)

  const fallback = await pre(baseExec('allow-command'), next)
  assert.equal(fallback.kind, 'ask')
  assert.match(fallback.reason, /Caushell could not analyze this shell action/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, { adapterPath: adapter, storeRoot: join(root, 'store-invalid-context') })
  const pre = harness.pre()
  assert.ok(pre)

  const missingAgentId = baseExec('allow-command')
  missingAgentId.agent = { id: undefined, session: { header: { cwd: root } } }
  const missingAgentResult = await pre(missingAgentId, next)
  assert.equal(missingAgentResult.kind, 'ask')
  assert.match(missingAgentResult.reason, /agent id must be a non-empty string/)

  const missingCallId = baseExec('allow-command')
  missingCallId.callId = undefined
  const missingCallResult = await pre(missingCallId, next)
  assert.equal(missingCallResult.kind, 'ask')
  assert.match(missingCallResult.reason, /call id must be a non-empty string/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, {
    adapterPath: '/does/not/exist',
    storeRoot: join(root, 'store-fallback-deny'),
    failureAction: 'deny',
  })
  const pre = harness.pre()
  assert.ok(pre)

  const exec = baseExec('allow-command')
  const fallback = await pre(exec, next)
  assert.match(fallback.reason, /Caushell could not analyze this shell action/)
  assert.equal(fallback.kind, 'deny')
  assert.match(harness.guard(exec), /Caushell could not analyze this shell action/)
  harness.cleanup()
}

{
  const harness = createContext()
  apply(harness.ctx, {
    adapterPath: '/does/not/exist',
    storeRoot: join(root, 'store-fallback-allow'),
    failureAction: 'allow',
  })
  const downstream = await harness.pre()(baseExec('allow-command'), async () => ({
    kind: 'deny',
    reason: 'downstream still applies',
  }))
  assert.deepEqual(downstream, { kind: 'deny', reason: 'downstream still applies' })
  harness.cleanup()
}

assert.throws(
  () => apply(createContext().ctx, { storeRoot: join(root, 'store-invalid-config'), timeoutMs: 0 }),
  /timeoutMs must be a positive safe integer/,
)
assert.throws(
  () => apply(createContext().ctx, { storeRoot: join(root, 'store-invalid-field'), typo: true }),
  /unknown field "typo"/,
)

console.log('deepseek-harness plugin smoke: ok')
