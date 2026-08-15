import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

export const name = 'caushell-dsh-bash'
export const inject = ['tools']

const SERVICE_NAME = 'caushellDshBash'
const PROTOCOL_SCHEMA_VERSION = 1
const DEFAULT_TIMEOUT_MS = 2_000
const DEFAULT_FAILURE_ACTION = 'need_approval'
const FAILURE_ACTIONS = new Set(['allow', 'deny', 'need_approval'])
const CONFIG_KEYS = new Set(['adapterPath', 'configPath', 'storeRoot', 'failureAction', 'timeoutMs'])
const FALLBACK_REASON = '[Caushell] Caushell could not analyze this shell action, so approval is required by the current DSH plugin configuration.\nIf you want this DSH integration to allow shell actions when analysis is unavailable, set failureAction: allow in the caushell-dsh-bash plugin configuration.'
const UNSUPPORTED_BASH_REASON = '[Caushell] This integration supports ordinary DSH Bash only. The current bash invocation does not expose the ordinary Bash arguments, so Caushell will not analyze it as a fresh shell.'

/**
 * Guard the ordinary non-persistent DSH `bash` tool before execution.
 *
 * Persistent Bash registers the same tool name with a different argument set.
 * Calls without the ordinary Bash arguments are denied instead of being
 * analyzed with a false fresh-shell state.
 */
export function apply(ctx, config = {}) {
  const resolved = resolveConfig(config)
  const client = new AdapterClient({
    adapterPath: resolved.adapterPath,
    configPath: resolved.configPath,
    storeRoot: resolved.storeRoot,
    timeoutMs: resolved.timeoutMs,
    logger: ctx.logger,
  })
  const deniedExecutions = new WeakMap()

  // The provided service makes duplicate policy mounts fail at composition
  // time and gives integration smokes a readiness dependency.
  ctx.provide(SERVICE_NAME, Object.freeze({ mode: 'ordinary-bash' }))

  // Reassert hard denials after the reorderable pre-execute waterfall so an
  // outer listener cannot turn a Caushell denial into permission.
  ctx.tools.guard((exec) => {
    const reason = deniedExecutions.get(exec)
    if (reason === undefined) return undefined
    deniedExecutions.delete(exec)
    return reason
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.name !== 'bash') return next()

    const args = exec.arguments
    if (!isOrdinaryBashArguments(args)) {
      return denyMonotonically(UNSUPPORTED_BASH_REASON, exec, next, deniedExecutions)
    }

    let request
    try {
      request = buildRequest(ctx, exec, args)
    } catch (error) {
      return fallbackDecision(resolved.failureAction, error, exec, next, deniedExecutions)
    }

    let result
    try {
      result = await client.check(request, exec.signal)
    } catch (error) {
      return fallbackDecision(resolved.failureAction, error, exec, next, deniedExecutions)
    }

    if (result.error !== undefined) {
      return fallbackDecision(
        resolved.failureAction,
        new Error(result.error),
        exec,
        next,
        deniedExecutions,
      )
    }

    const reason = userVisibleReason(result.reason ?? defaultReason(result.decision))
    switch (result.decision) {
      case 'allow':
        return next()
      case 'ask':
        return requireApproval(reason, next)
      case 'deny':
        return denyMonotonically(reason, exec, next, deniedExecutions)
      default:
        throw new Error(`unreachable Caushell DSH decision ${String(result.decision)}`)
    }
  }, { prepend: true })

  ctx.effect(() => () => client.close())
}

class AdapterClient {
  constructor(options) {
    this.options = options
    this.child = undefined
    this.starting = undefined
    this.pending = new Map()
    this.closed = false
  }

  async check(request, signal) {
    if (this.closed) throw new Error('Caushell DSH plugin is disposed')
    if (signal?.aborted) throw new Error('Caushell DSH check was cancelled')
    const generation = await this.ensureStarted()
    if (signal?.aborted) throw new Error('Caushell DSH check was cancelled')

    return new Promise((resolvePromise, rejectPromise) => {
      const requestId = request.request_id
      if (this.pending.has(requestId)) {
        rejectPromise(new Error(`duplicate Caushell DSH request id ${requestId}`))
        return
      }

      let settled = false
      let timer
      let entry
      const cleanup = () => {
        if (timer !== undefined) clearTimeout(timer)
        signal?.removeEventListener('abort', onAbort)
        if (this.pending.get(requestId) === entry) this.pending.delete(requestId)
      }
      const resolveOnce = (value) => {
        if (settled) return
        settled = true
        cleanup()
        resolvePromise(value)
      }
      const rejectOnce = (error) => {
        if (settled) return
        settled = true
        cleanup()
        rejectPromise(error)
      }
      const abandonGeneration = (error) => {
        this.retireGeneration(generation, error, true)
      }
      const onAbort = () => {
        abandonGeneration(new Error('Caushell DSH check was cancelled'))
      }

      entry = { generation, resolve: resolveOnce, reject: rejectOnce }
      this.pending.set(requestId, entry)
      signal?.addEventListener('abort', onAbort, { once: true })
      timer = setTimeout(() => {
        abandonGeneration(new Error(`Caushell DSH check timed out after ${this.options.timeoutMs}ms`))
      }, this.options.timeoutMs)

      if (this.child !== generation || generation.process.stdin.destroyed) {
        rejectOnce(new Error('Caushell DSH adapter is not writable'))
        return
      }
      try {
        generation.process.stdin.write(`${JSON.stringify(request)}\n`, (error) => {
          if (error !== undefined && error !== null) abandonGeneration(error)
        })
      } catch (error) {
        abandonGeneration(error)
      }
    })
  }

  async ensureStarted() {
    if (this.closed) throw new Error('Caushell DSH plugin is disposed')
    if (this.child !== undefined) return this.child
    if (this.starting !== undefined) return this.starting

    const starting = new Promise((resolvePromise, rejectPromise) => {
      let process
      let startupSettled = false
      try {
        const args = ['--store', this.options.storeRoot]
        if (this.options.configPath !== undefined) args.push('--config', this.options.configPath)
        process = spawn(this.options.adapterPath, args, {
          stdio: ['pipe', 'pipe', 'pipe'],
          env: processEnv(),
        })
      } catch (error) {
        rejectPromise(error)
        return
      }

      const generation = {
        process,
        lines: createInterface({ input: process.stdout }),
      }
      this.child = generation
      generation.lines.on('line', (line) => this.handleLine(generation, line))
      process.stderr.on('data', (chunk) => {
        this.options.logger?.debug?.(`caushell-dsh-bash: ${String(chunk).trimEnd()}`)
      })
      process.on('error', (error) => {
        this.retireGeneration(generation, error, false)
        if (!startupSettled) {
          startupSettled = true
          rejectPromise(error)
        }
      })
      process.once('close', (code, signal) => {
        const error = new Error(`caushell-adapter-dsh exited before responding (code=${code}, signal=${signal ?? 'none'})`)
        this.retireGeneration(generation, error, false)
        if (!startupSettled) {
          startupSettled = true
          rejectPromise(error)
        }
      })
      process.stdin.on('error', (error) => this.retireGeneration(generation, error, true))
      process.once('spawn', () => {
        if (startupSettled) return
        if (this.closed) {
          startupSettled = true
          this.retireGeneration(generation, new Error('Caushell DSH plugin is disposed'), true)
          rejectPromise(new Error('Caushell DSH plugin is disposed'))
          return
        }
        startupSettled = true
        resolvePromise(generation)
      })
    })
    this.starting = starting
    try {
      return await starting
    } finally {
      if (this.starting === starting) this.starting = undefined
    }
  }

  handleLine(generation, line) {
    let response
    try {
      response = JSON.parse(line)
    } catch (error) {
      this.retireGeneration(
        generation,
        new Error(`invalid caushell-adapter-dsh response: ${error.message}`),
        true,
      )
      return
    }
    const validationError = validateResponse(response)
    if (validationError !== undefined) {
      this.retireGeneration(
        generation,
        new Error(`invalid caushell-adapter-dsh response: ${validationError}`),
        true,
      )
      return
    }
    const pending = this.pending.get(response.request_id)
    if (pending === undefined || pending.generation !== generation) return
    pending.resolve(response)
  }

  failGeneration(generation, error) {
    for (const pending of this.pending.values()) {
      if (pending.generation === generation) pending.reject(error)
    }
  }

  retireGeneration(generation, error, terminate) {
    if (this.child === generation) this.child = undefined
    this.failGeneration(generation, error)
    generation.lines.close()
    if (terminate && generation.process.exitCode === null && generation.process.signalCode === null) {
      generation.process.stdin.destroy()
      generation.process.kill()
    }
  }

  close() {
    if (this.closed) return
    this.closed = true
    const error = new Error('Caushell DSH plugin disposed')
    if (this.child !== undefined) this.retireGeneration(this.child, error, true)
    for (const pending of this.pending.values()) pending.reject(error)
  }
}

function buildRequest(ctx, exec, args) {
  const agent = exec.agent
  if (agent === undefined) {
    throw new Error('ordinary DSH Bash call has no agent session')
  }
  const sessionId = nonEmptyString('ordinary DSH Bash agent id', agent.id)
  const requestId = nonEmptyString('ordinary DSH Bash call id', exec.callId)

  const sessionCwd = agent.session?.header?.cwd
  const sandboxPolicy = ctx.get?.('sandboxPolicy')
  const policyRoot = sandboxPolicy?.resolve?.({ session: agent.session })?.workspaceRoot
  const workspaceRoot = policyRoot ?? sessionCwd
  if (typeof workspaceRoot !== 'string' || !isAbsolute(workspaceRoot)) {
    throw new Error('ordinary DSH Bash workspace root is unavailable or not absolute')
  }

  const cwd = resolveCallCwd(args.workdir, workspaceRoot)
  return {
    schema_version: PROTOCOL_SCHEMA_VERSION,
    request_id: requestId,
    session_id: sessionId,
    cwd,
    command: args.command,
    workspace_root: workspaceRoot,
  }
}

function nonEmptyString(label, value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string`)
  }
  return value
}

function validateResponse(value) {
  if (!isRecord(value)) return 'response must be an object'
  if (value.schema_version !== PROTOCOL_SCHEMA_VERSION) {
    return `schema_version must be ${PROTOCOL_SCHEMA_VERSION}`
  }
  if (typeof value.request_id !== 'string' || value.request_id.length === 0) {
    return 'request_id must be a non-empty string'
  }
  const hasDecision = Object.hasOwn(value, 'decision')
  const hasError = Object.hasOwn(value, 'error')
  if (hasDecision === hasError) return 'response must contain exactly one of decision or error'
  if (hasDecision && !['allow', 'ask', 'deny'].includes(value.decision)) {
    return `unknown decision ${String(value.decision)}`
  }
  if (hasError && (typeof value.error !== 'string' || value.error.length === 0)) {
    return 'error must be a non-empty string'
  }
  if (value.reason !== undefined && typeof value.reason !== 'string') return 'reason must be a string'
  if (hasError && value.reason !== undefined) return 'error response must not contain reason'

  const allowedKeys = new Set(hasDecision
    ? ['schema_version', 'request_id', 'decision', 'reason']
    : ['schema_version', 'request_id', 'error'])
  const unknownKey = Object.keys(value).find((key) => !allowedKeys.has(key))
  if (unknownKey !== undefined) return `unknown response field ${JSON.stringify(unknownKey)}`
}

function resolveConfig(value) {
  if (!isRecord(value)) throw new TypeError('caushell-dsh-bash config must be an object')
  const unknownKey = Object.keys(value).find((key) => !CONFIG_KEYS.has(key))
  if (unknownKey !== undefined) {
    throw new TypeError(`caushell-dsh-bash config has unknown field ${JSON.stringify(unknownKey)}`)
  }

  const failureAction = value.failureAction ?? DEFAULT_FAILURE_ACTION
  if (!FAILURE_ACTIONS.has(failureAction)) {
    throw new TypeError('caushell-dsh-bash failureAction must be allow, deny, or need_approval')
  }
  const timeoutMs = value.timeoutMs ?? DEFAULT_TIMEOUT_MS
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('caushell-dsh-bash timeoutMs must be a positive safe integer')
  }

  return {
    adapterPath: optionalAbsolutePath(
      'adapterPath',
      value.adapterPath ?? process.env.CAUSHELL_DSH_ADAPTER_PATH,
    ) ?? 'caushell-adapter-dsh',
    configPath: optionalAbsolutePath(
      'configPath',
      value.configPath ?? process.env.CAUSHELL_CONFIG_PATH,
    ),
    storeRoot: resolveStoreRoot(value.storeRoot),
    failureAction,
    timeoutMs,
  }
}

function optionalAbsolutePath(label, value) {
  if (value === undefined) return undefined
  if (typeof value !== 'string' || value.length === 0 || !isAbsolute(value)) {
    throw new TypeError(`caushell-dsh-bash ${label} must be an absolute path`)
  }
  return resolve(value)
}

function resolveStoreRoot(configured) {
  const selected = configured ?? process.env.CAUSHELL_DSH_STORE_ROOT
  if (selected !== undefined) return optionalAbsolutePath('storeRoot', selected)
  const stateHome = process.env.XDG_STATE_HOME
  if (stateHome !== undefined) {
    return join(optionalAbsolutePath('XDG_STATE_HOME', stateHome), 'caushell', 'deepseek-harness', 'sessions')
  }
  return join(homedir(), '.local', 'state', 'caushell', 'deepseek-harness', 'sessions')
}

function resolveCallCwd(workdir, workspaceRoot) {
  if (workdir === undefined || workdir.length === 0) return workspaceRoot
  return isAbsolute(workdir) ? resolve(workdir) : resolve(workspaceRoot, workdir)
}

function isOrdinaryBashArguments(value) {
  return isRecord(value)
    && typeof value.command === 'string'
    && value.command.trim().length > 0
    && typeof value.description === 'string'
    && value.description.trim().length > 0
    && (value.workdir === undefined || typeof value.workdir === 'string')
}

async function requireApproval(reason, next) {
  const downstream = await next()
  switch (downstream.kind) {
    case 'allow':
      return { kind: 'ask', reason }
    case 'ask':
      return { kind: 'ask', reason: joinReasons(reason, downstream.reason) }
    case 'deny':
      return downstream
    default:
      throw new Error(`invalid downstream DSH pre-execute decision ${String(downstream.kind)}`)
  }
}

async function denyMonotonically(reason, exec, next, deniedExecutions) {
  deniedExecutions.set(exec, reason)
  const downstream = await next()
  if (downstream.kind === 'deny') return downstream
  if (downstream.kind !== 'allow' && downstream.kind !== 'ask') {
    throw new Error(`invalid downstream DSH pre-execute decision ${String(downstream.kind)}`)
  }
  return { kind: 'deny', reason }
}

function fallbackDecision(action, error, exec, next, deniedExecutions) {
  const detail = error instanceof Error ? error.message : String(error)
  if (action === 'allow') return next()
  if (action === 'deny') {
    return denyMonotonically(
      userVisibleReason(`Caushell could not analyze this shell action: ${detail}`),
      exec,
      next,
      deniedExecutions,
    )
  }
  return requireApproval(`${FALLBACK_REASON}\nDetail: ${detail}`, next)
}

function joinReasons(first, second) {
  if (typeof second !== 'string' || second.length === 0 || second === first) return first
  return `${first}\n${second}`
}

function defaultReason(decision) {
  if (decision === 'ask') return 'shell query policy requires explicit approval'
  if (decision === 'deny') return 'shell query policy denied the command'
  return ''
}

function userVisibleReason(reason) {
  const prefix = '[Caushell] '
  return reason.startsWith(prefix) ? reason : `${prefix}${reason}`
}

function processEnv() {
  return process.env
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
