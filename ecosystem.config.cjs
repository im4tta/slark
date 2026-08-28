module.exports = {
  apps: [{
    name: 'slark-playground',
    script: 'npx',
    args: 'serve -l 3000 --no-clipboard .',
    watch: false,
    instances: 1,
    exec_mode: 'fork'
  }]
}
