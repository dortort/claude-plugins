import { benignEval } from './benign.ts'
import { injectionEval } from './injection.ts'

const injection = injectionEval()
const benign = benignEval()

console.log([injection.report, '', benign.report, ''].join('\n'))

const missed = [
  ...(injection.pass ? [] : ['injection eval']),
  ...(benign.pass ? [] : ['benign-task eval']),
]
if (missed.length > 0) {
  console.log(`Targets missed: ${missed.join(', ')}.`)
  process.exitCode = 1
} else {
  console.log('All targets met.')
}
