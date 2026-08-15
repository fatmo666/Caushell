import { mkdir } from 'node:fs/promises'

export const name = 'caushell-dsh-real-smoke'
export const inject = ['tools', 'appExit', 'agents', 'caushellDshBash']

export function apply(ctx) {
  queueMicrotask(async () => {
    let handle
    try {
      await waitForTool(ctx.tools, 'bash')
      await mkdir('/workspace', { recursive: true })
      handle = await ctx.agents.create({
        sessionId: 'caushell-dsh-real-smoke-agent',
        meta: { cwd: '/workspace' },
      })
      const agent = handle.agent
      const allow = await ctx.tools.execute({
        callId: 'caushell-dsh-real-allow',
        name: 'bash',
        agent,
        arguments: {
          command: 'printf hello',
          description: 'Print a harmless value',
        },
        signal: new AbortController().signal,
      })
      assertSuccessful(allow, 'ordinary Bash allow path')

      const deny = await ctx.tools.execute({
        callId: 'caushell-dsh-real-deny',
        name: 'bash',
        agent,
        arguments: {
          command: 'rm -rf /etc/*',
          description: 'Delete a system directory',
        },
        signal: new AbortController().signal,
      })
      assertDeniedByCaushell(deny)

      const stillThere = await ctx.tools.execute({
        callId: 'caushell-dsh-real-post-deny',
        name: 'bash',
        agent,
        arguments: {
          command: 'test -e /etc/passwd',
          description: 'Check a system file exists',
        },
        signal: new AbortController().signal,
      })
      assertSuccessful(stillThere, 'post-deny shell remains usable')
      await handle.dispose()
      ctx.get('appExit')(0)
    } catch (error) {
      await handle?.dispose()
      console.error(`caushell-dsh-real-smoke: ${error instanceof Error ? error.stack : String(error)}`)
      ctx.get('appExit')(1)
    }
  })
}

async function waitForTool(tools, name) {
  const deadline = Date.now() + 2_000
  while (tools.get(name) === undefined) {
    if (Date.now() >= deadline) throw new Error(`tool ${JSON.stringify(name)} was not registered`)
    await new Promise(resolve => setTimeout(resolve, 10))
  }
}

function assertSuccessful(result, label) {
  if (result.isError === true) {
    throw new Error(`${label} failed: ${JSON.stringify(result)}`)
  }
}

function assertDeniedByCaushell(result) {
  if (result.isError !== true) {
    throw new Error(`dangerous command was not denied: ${JSON.stringify(result)}`)
  }
  const message = result.error?.message ?? result.content?.map((block) => block.text ?? '').join('\n') ?? ''
  if (!/Caushell|system path|delete/i.test(message)) {
    throw new Error(`dangerous command was denied without a Caushell reason: ${JSON.stringify(result)}`)
  }
}
