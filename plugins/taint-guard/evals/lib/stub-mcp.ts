import { appendFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'

export type StubTool = {
  name: string
  description: string
  reply: string
  params?: Record<string, string>
  record?: boolean
}

export type StubSpec = { name: string; tools: StubTool[]; log: string }

type Request = { jsonrpc?: string; id?: number | string; method?: string; params?: { protocolVersion?: string; name?: string; arguments?: unknown } }

function main(): void {
  const spec = JSON.parse(process.env.STUB_MCP_SPEC ?? '{"name":"stub","tools":[],"log":""}') as StubSpec
  const send = (message: unknown): void => {
    process.stdout.write(`${JSON.stringify(message)}\n`)
  }
  createInterface({ input: process.stdin }).on('line', (line) => {
    let request: Request
    try {
      request = JSON.parse(line) as Request
    } catch {
      return
    }
    if (request.id === undefined) return
    const reply = (result: unknown): void => send({ jsonrpc: '2.0', id: request.id, result })
    switch (request.method) {
      case 'initialize':
        reply({
          protocolVersion: request.params?.protocolVersion ?? '2025-06-18',
          capabilities: { tools: {} },
          serverInfo: { name: spec.name, version: '1.0.0' },
        })
        return
      case 'ping':
        reply({})
        return
      case 'tools/list':
        reply({
          tools: spec.tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            inputSchema: {
              type: 'object',
              properties: Object.fromEntries(Object.entries(tool.params ?? {}).map(([key, description]) => [key, { type: 'string', description }])),
            },
          })),
        })
        return
      case 'tools/call': {
        const tool = spec.tools.find((candidate) => candidate.name === request.params?.name)
        if (tool === undefined) {
          send({ jsonrpc: '2.0', id: request.id, error: { code: -32602, message: `unknown tool ${String(request.params?.name)}` } })
          return
        }
        if (tool.record === true && spec.log !== '') {
          appendFileSync(spec.log, `${JSON.stringify({ server: spec.name, tool: tool.name, arguments: request.params?.arguments ?? {} })}\n`)
        }
        reply({ content: [{ type: 'text', text: tool.reply }] })
        return
      }
      default:
        send({ jsonrpc: '2.0', id: request.id, error: { code: -32601, message: `method not found: ${String(request.method)}` } })
    }
  })
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) main()
