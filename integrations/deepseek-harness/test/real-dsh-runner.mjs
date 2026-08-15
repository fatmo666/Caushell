import { mkdir, symlink, writeFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { join } from 'node:path'

const dshHome = process.env.DSH_HOME
const dshCli = process.env.CAUSHELL_DSH_CLI_PATH
const overlay = process.env.CAUSHELL_DSH_OVERLAY_PATH
const packagePath = process.env.CAUSHELL_DSH_PACKAGE_PATH
const installPackagePath = process.env.CAUSHELL_DSH_INSTALL_PACKAGE_PATH
const profileName = 'smoke'

if (!dshHome || !dshCli || !overlay || !packagePath) {
  throw new Error('DSH_HOME, CAUSHELL_DSH_CLI_PATH, CAUSHELL_DSH_OVERLAY_PATH, and CAUSHELL_DSH_PACKAGE_PATH are required')
}

if (installPackagePath === undefined) {
  const profileDir = join(dshHome, 'profiles', profileName)
  await mkdir(profileDir, { recursive: true })
  await writeFile(
    join(profileDir, 'package.json'),
    JSON.stringify({
      name: 'caushell-dsh-real-smoke',
      private: true,
      dsh: { profile: { bundles: ['@deepseek-ai/dsh-base'] } },
    }) + '\n',
  )
  await writeFile(join(profileDir, 'cordis.patch.yml'), '[]\n')
  await mkdir(join(profileDir, 'node_modules'), { recursive: true })
  await symlink(packagePath, join(profileDir, 'node_modules', 'caushell-dsh-bash'))
} else {
  const enable = spawn('corepack', ['enable'], {
    stdio: 'inherit',
    env: process.env,
  })
  await new Promise((resolve, reject) => {
    enable.once('error', reject)
    enable.once('exit', code => code === 0 ? resolve() : reject(new Error(`corepack enable exited with ${code}`)))
  })
  const install = spawn(process.execPath, [dshCli, 'plugin', '--profile', profileName, 'add', installPackagePath], {
    stdio: 'inherit',
    env: process.env,
  })
  await new Promise((resolve, reject) => {
    install.once('error', reject)
    install.once('exit', code => code === 0 ? resolve() : reject(new Error(`dsh plugin add exited with ${code}`)))
  })
}

const child = spawn(process.execPath, [
  dshCli,
  '--profile',
  profileName,
  '--patch',
  overlay,
], {
  stdio: 'inherit',
  env: process.env,
})

child.once('error', (error) => {
  console.error(`caushell-dsh-real-smoke: failed to start DSH: ${error.message}`)
  process.exit(1)
})

child.once('exit', (code, signal) => {
  if (signal !== null) process.kill(process.pid, signal)
  else process.exit(code ?? 1)
})
