module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', [
      'feat',     // new feature
      'fix',      // bug fix
      'docs',     // documentation
      'style',    // formatting (no code change)
      'refactor', // code restructuring
      'perf',     // performance improvement
      'test',     // adding/updating tests
      'build',    // build system or deps
      'ci',       // CI/CD changes
      'chore',    // maintenance
      'revert',   // revert a commit
      'security', // security fix
    ]],
    'subject-case': [0], // allow any case
  },
};
